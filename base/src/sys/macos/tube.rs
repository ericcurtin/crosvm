// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! macOS-specific Tube send/recv using SOCK_STREAM with a u64 length-prefix framing protocol.
//!
//! macOS does not support SOCK_SEQPACKET for Unix domain sockets; UnixSeqpacket falls back to
//! SOCK_STREAM, which provides no message boundaries. A u64 little-endian length header is
//! prepended to each message so the receiver can reconstruct message boundaries.

use std::io::IoSlice;
#[cfg(feature = "proto_tube")]
use std::os::unix::prelude::RawFd;

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::descriptor_reflection::deserialize_with_descriptors;
use crate::descriptor_reflection::SerializeDescriptors;
use crate::handle_eintr;
use crate::sys::unix::descriptor::set_descriptor_cloexec;
use crate::sys::unix::net::socketpair;
use crate::tube::Error;
use crate::tube::Result;
use crate::unix::tube::Tube;
#[cfg(feature = "proto_tube")]
use crate::unix::tube::TUBE_MAX_FDS;
use crate::SafeDescriptor;
use crate::ScmSocket;
use crate::UnixSeqpacket;
use crate::SCM_SOCKET_MAX_FD_COUNT;

impl Tube {
    /// Create a pair of connected tubes. Uses a SOCK_STREAM socket pair directly, since
    /// macOS does not support SOCK_SEQPACKET. Message framing is provided by the send/recv
    /// methods via a u64 length header.
    pub fn pair() -> Result<(Tube, Tube)> {
        // Create a SOCK_STREAM socket pair directly; do not go through UnixSeqpacket::pair()
        // because macOS does not support SOCK_SEQPACKET and we want to be explicit about
        // the underlying transport.
        let (fd0, fd1) = socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0).map_err(Error::Pair)?;
        // Set CLOEXEC on both ends (socketpair on macOS can race with fork/exec otherwise).
        set_descriptor_cloexec(&fd0).map_err(|e| Error::Pair(e.into()))?;
        set_descriptor_cloexec(&fd1).map_err(|e| Error::Pair(e.into()))?;
        fn make_tube(sd: SafeDescriptor) -> Result<Tube> {
            let sock = UnixSeqpacket::from(sd);
            // Set SO_NOSIGPIPE so writes to a closed peer return EPIPE instead of SIGPIPE.
            let scm: ScmSocket<UnixSeqpacket> = sock.try_into().map_err(Error::ScmSocket)?;
            Ok(Tube { socket: scm })
        }
        let tube1 = make_tube(fd0)?;
        let tube2 = make_tube(fd1)?;
        Ok((tube1, tube2))
    }

    /// Sends a message with at most `max_fds` file descriptors via a Tube.
    ///
    /// Prepends a u64 little-endian length header to the message because the underlying
    /// SOCK_STREAM socket provides no message boundaries.
    pub fn send_with_max_fds<T: Serialize>(&self, msg: &T, max_fds: usize) -> Result<()> {
        if max_fds > SCM_SOCKET_MAX_FD_COUNT {
            return Err(Error::SendTooManyFds);
        }
        let msg_serialize = SerializeDescriptors::new(&msg);
        let msg_json = serde_json::to_vec(&msg_serialize).map_err(Error::Json)?;
        let msg_descriptors = msg_serialize.into_descriptors();

        if msg_descriptors.len() > max_fds {
            return Err(Error::SendTooManyFds);
        }

        // Prepend a u64 length header so the receiver knows how many bytes to read.
        let len_bytes = (msg_json.len() as u64).to_le_bytes();
        handle_eintr!(self.socket.send_vectored_with_fds(
            &[IoSlice::new(&len_bytes), IoSlice::new(&msg_json),],
            &msg_descriptors
        ))
        .map_err(Error::Send)?;
        Ok(())
    }

    /// Receives a message with at most `max_fds` file descriptors from a Tube.
    ///
    /// Reads the u64 length header first, then reads the message body.
    pub fn recv_with_max_fds<T: DeserializeOwned>(&self, max_fds: usize) -> Result<T> {
        if max_fds > SCM_SOCKET_MAX_FD_COUNT {
            return Err(Error::RecvTooManyFds);
        }

        // Read the length header (file descriptors arrive with this first recvmsg).
        let mut header_buf = [0u8; std::mem::size_of::<u64>()];
        let (header_read, msg_descriptors) = self.recv_stream_exact(&mut header_buf, max_fds)?;
        if header_read == 0 {
            return Err(Error::Disconnected);
        }
        let msg_size = u64::from_le_bytes(header_buf) as usize;
        let mut msg_json = vec![0u8; msg_size];
        if msg_size > 0 {
            let (body_read, _) = self.recv_stream_exact(&mut msg_json, 0)?;
            if body_read == 0 {
                return Err(Error::Disconnected);
            }
        }
        let msg_json_size = msg_size;

        if msg_json_size == 0 {
            return Err(Error::Disconnected);
        }

        deserialize_with_descriptors(
            || serde_json::from_slice(&msg_json[0..msg_json_size]),
            msg_descriptors,
        )
        .map_err(Error::Json)
    }

    /// Reads exactly `buf.len()` bytes from a SOCK_STREAM socket, handling partial reads.
    ///
    /// File descriptors (via SCM_RIGHTS) are only requested on the first recvmsg call;
    /// subsequent calls for the same logical message pass `max_fds=0`.
    fn recv_stream_exact(
        &self,
        buf: &mut [u8],
        max_fds: usize,
    ) -> Result<(usize, Vec<SafeDescriptor>)> {
        let mut total_read = 0;
        let mut all_fds = Vec::new();
        while total_read < buf.len() {
            let fds_to_recv = if total_read == 0 { max_fds } else { 0 };
            let (n, fds) = handle_eintr!(self
                .socket
                .recv_with_fds(&mut buf[total_read..], fds_to_recv))
            .map_err(Error::Recv)?;
            if n == 0 {
                if total_read == 0 {
                    return Ok((0, all_fds));
                }
                return Err(Error::Disconnected);
            }
            all_fds.extend(fds);
            total_read += n;
        }
        Ok((total_read, all_fds))
    }

    #[cfg(feature = "proto_tube")]
    pub(crate) fn send_proto_impl<M: protobuf::Message>(&self, msg: &M) -> Result<()> {
        let bytes = msg.write_to_bytes().map_err(Error::Proto)?;
        let no_fds: [RawFd; 0] = [];
        let len_bytes = (bytes.len() as u64).to_le_bytes();
        handle_eintr!(self
            .socket
            .send_vectored_with_fds(&[IoSlice::new(&len_bytes), IoSlice::new(&bytes),], &no_fds))
        .map_err(Error::Send)?;
        Ok(())
    }

    #[cfg(feature = "proto_tube")]
    pub(crate) fn recv_proto_impl<M: protobuf::Message>(&self) -> Result<M> {
        let mut header_buf = [0u8; std::mem::size_of::<u64>()];
        let (header_read, _) = self.recv_stream_exact(&mut header_buf, TUBE_MAX_FDS)?;
        if header_read == 0 {
            return Err(Error::Disconnected);
        }
        let msg_size = u64::from_le_bytes(header_buf) as usize;
        let mut msg_bytes = vec![0u8; msg_size];
        if msg_size > 0 {
            let (body_read, _) = self.recv_stream_exact(&mut msg_bytes, 0)?;
            if body_read == 0 {
                return Err(Error::Disconnected);
            }
        }
        protobuf::Message::parse_from_bytes(&msg_bytes).map_err(Error::Proto)
    }
}
