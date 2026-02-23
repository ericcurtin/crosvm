// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::os::unix::prelude::AsRawFd;
use std::os::unix::prelude::RawFd;
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde::Serialize;

use crate::descriptor::AsRawDescriptor;
use crate::tube::Error;
use crate::tube::RecvTube;
use crate::tube::Result;
use crate::tube::SendTube;
use crate::RawDescriptor;
use crate::ReadNotifier;
use crate::ScmSocket;
use crate::UnixSeqpacket;

// This size matches the inline buffer size of CmsgBuffer.
pub(crate) const TUBE_MAX_FDS: usize = 32;

/// Bidirectional tube that support both send and recv.
#[derive(Serialize, Deserialize)]
pub struct Tube {
    pub(crate) socket: ScmSocket<UnixSeqpacket>,
}

impl Tube {
    /// DO NOT USE this method directly as it will become private soon (b/221484449). Use a
    /// directional Tube pair instead.
    #[deprecated]
    pub fn try_clone(&self) -> Result<Self> {
        self.socket
            .inner()
            .try_clone()
            .map_err(Error::Clone)?
            .try_into()
    }

    /// Sends a message via a Tube.
    /// The number of file descriptors that this method can send is limited to `TUBE_MAX_FDS`.
    /// If you want to send more descriptors, use `send_with_max_fds` instead.
    pub fn send<T: Serialize>(&self, msg: &T) -> Result<()> {
        self.send_with_max_fds(msg, TUBE_MAX_FDS)
    }

    /// Receives a message from a Tube.
    /// If the sender sent file descriptors more than TUBE_MAX_FDS with `send_with_max_fds`, use
    /// `recv_with_max_fds` instead.
    pub fn recv<T: DeserializeOwned>(&self) -> Result<T> {
        self.recv_with_max_fds(TUBE_MAX_FDS)
    }

    pub fn set_send_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.socket
            .inner()
            .set_write_timeout(timeout)
            .map_err(Error::SetSendTimeout)
    }

    pub fn set_recv_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.socket
            .inner()
            .set_read_timeout(timeout)
            .map_err(Error::SetRecvTimeout)
    }
}

impl TryFrom<UnixSeqpacket> for Tube {
    type Error = Error;

    fn try_from(socket: UnixSeqpacket) -> Result<Self> {
        Ok(Tube {
            socket: socket.try_into().map_err(Error::ScmSocket)?,
        })
    }
}

impl AsRawDescriptor for Tube {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.socket.as_raw_descriptor()
    }
}

impl AsRawFd for Tube {
    fn as_raw_fd(&self) -> RawFd {
        self.socket.inner().as_raw_descriptor()
    }
}

impl ReadNotifier for Tube {
    fn get_read_notifier(&self) -> &dyn AsRawDescriptor {
        &self.socket
    }
}

impl AsRawDescriptor for SendTube {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.0.as_raw_descriptor()
    }
}

impl AsRawDescriptor for RecvTube {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.0.as_raw_descriptor()
    }
}

/// Wrapper for Tube used for sending and receiving protos - avoids extra overhead of serialization
/// via serde_json. Since protos should be standalone objects we do not support sending of file
/// descriptors as a normal Tube would.
#[cfg(feature = "proto_tube")]
pub struct ProtoTube(Tube);

#[cfg(feature = "proto_tube")]
impl ProtoTube {
    pub fn pair() -> Result<(ProtoTube, ProtoTube)> {
        Tube::pair().map(|(t1, t2)| (ProtoTube(t1), ProtoTube(t2)))
    }

    pub fn send_proto<M: protobuf::Message>(&self, msg: &M) -> Result<()> {
        self.0.send_proto_impl(msg)
    }

    pub fn recv_proto<M: protobuf::Message>(&self) -> Result<M> {
        self.0.recv_proto_impl()
    }
}

#[cfg(feature = "proto_tube")]
impl From<Tube> for ProtoTube {
    fn from(tube: Tube) -> Self {
        ProtoTube(tube)
    }
}

#[cfg(all(feature = "proto_tube", test))]
#[allow(unused_variables)]
mod tests {
    // not testing this proto specifically, just need an existing one to test the ProtoTube.
    use protos::cdisk_spec::ComponentDisk;

    use super::*;

    #[test]
    fn tube_serializes_and_deserializes() {
        let (pt1, pt2) = ProtoTube::pair().unwrap();
        let proto = ComponentDisk {
            file_path: "/some/cool/path".to_string(),
            offset: 99,
            ..ComponentDisk::new()
        };

        pt1.send_proto(&proto).unwrap();

        let recv_proto = pt2.recv_proto().unwrap();

        assert!(proto.eq(&recv_proto));
    }
}
