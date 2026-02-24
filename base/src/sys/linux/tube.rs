// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Linux-specific Tube send/recv using SOCK_SEQPACKET message boundaries.

#[cfg(feature = "proto_tube")]
use std::os::unix::prelude::RawFd;

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::descriptor_reflection::deserialize_with_descriptors;
use crate::descriptor_reflection::SerializeDescriptors;
use crate::handle_eintr;
use crate::tube::Error;
use crate::tube::Result;
use crate::unix::tube::Tube;
#[cfg(feature = "proto_tube")]
use crate::unix::tube::TUBE_MAX_FDS;
use crate::UnixSeqpacket;
use crate::SCM_SOCKET_MAX_FD_COUNT;

impl Tube {
    /// Create a pair of connected tubes backed by SOCK_SEQPACKET.
    pub fn pair() -> Result<(Tube, Tube)> {
        let (socket1, socket2) = UnixSeqpacket::pair().map_err(Error::Pair)?;
        let tube1 = Tube::try_from(socket1)?;
        let tube2 = Tube::try_from(socket2)?;
        Ok((tube1, tube2))
    }

    /// Sends a message with at most `max_fds` file descriptors via a Tube.
    /// Note that `max_fds` must not exceed `SCM_SOCKET_MAX_FD_COUNT` (= 253).
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

        handle_eintr!(self.socket.send_with_fds(&msg_json, &msg_descriptors))
            .map_err(Error::Send)?;
        Ok(())
    }

    /// Receives a message with at most `max_fds` file descriptors from a Tube.
    pub fn recv_with_max_fds<T: DeserializeOwned>(&self, max_fds: usize) -> Result<T> {
        if max_fds > SCM_SOCKET_MAX_FD_COUNT {
            return Err(Error::RecvTooManyFds);
        }

        // WARNING: The `cros_async` and `base_tokio` tube wrappers both assume
        // that, if the tube is readable, then a call to `Tube::recv` will not
        // block (which ought to be true since we use SOCK_SEQPACKET and a single
        // recvmsg call currently).
        let msg_size =
            handle_eintr!(self.socket.inner().next_packet_size()).map_err(Error::Recv)?;
        // This buffer is the right size, as the size received in
        // next_packet_size() represents the size of only the message itself and
        // not the file descriptors. The descriptors are stored separately in
        // msghdr::msg_control.
        let mut msg_json = vec![0u8; msg_size];
        let (msg_json_size, msg_descriptors) =
            handle_eintr!(self.socket.recv_with_fds(&mut msg_json, max_fds))
                .map_err(Error::Recv)?;

        if msg_json_size == 0 {
            return Err(Error::Disconnected);
        }

        deserialize_with_descriptors(
            || serde_json::from_slice(&msg_json[0..msg_json_size]),
            msg_descriptors,
        )
        .map_err(Error::Json)
    }

    #[cfg(feature = "proto_tube")]
    pub(crate) fn send_proto_impl<M: protobuf::Message>(&self, msg: &M) -> Result<()> {
        let bytes = msg.write_to_bytes().map_err(Error::Proto)?;
        let no_fds: [RawFd; 0] = [];
        handle_eintr!(self.socket.send_with_fds(&bytes, &no_fds)).map_err(Error::Send)?;
        Ok(())
    }

    #[cfg(feature = "proto_tube")]
    pub(crate) fn recv_proto_impl<M: protobuf::Message>(&self) -> Result<M> {
        let msg_size =
            handle_eintr!(self.socket.inner().next_packet_size()).map_err(Error::Recv)?;
        let mut msg_bytes = vec![0u8; msg_size];
        let (msg_bytes_size, _) =
            handle_eintr!(self.socket.recv_with_fds(&mut msg_bytes, TUBE_MAX_FDS))
                .map_err(Error::Recv)?;
        if msg_bytes_size == 0 {
            return Err(Error::Disconnected);
        }
        protobuf::Message::parse_from_bytes(&msg_bytes).map_err(Error::Proto)
    }
}
