// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Re-export the shared ioctl wrapper functions and IoctlNr type from unix/ioctl_common.rs.
pub use crate::sys::unix::ioctl_common::*;
