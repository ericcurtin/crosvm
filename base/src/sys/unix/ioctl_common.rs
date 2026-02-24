// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Ioctl wrapper functions shared across Unix platforms.

// Allow missing safety comments because this file provides just thin helper functions for
// `libc::ioctl`. Their safety follows `libc::ioctl`'s safety.
#![allow(clippy::missing_safety_doc)]

use std::os::raw::c_int;
use std::os::raw::c_ulong;
use std::os::raw::c_void;

use crate::descriptor::AsRawDescriptor;

/// The ioctl number type. On Android and musl libc, ioctl takes a c_int; elsewhere c_ulong.
#[cfg(any(target_os = "android", target_env = "musl"))]
pub type IoctlNr = c_int;
#[cfg(not(any(target_os = "android", target_env = "musl")))]
pub type IoctlNr = c_ulong;

/// Run an ioctl with no arguments.
/// # Safety
/// The caller is responsible for determining the safety of the particular ioctl.
pub unsafe fn ioctl<F: AsRawDescriptor>(descriptor: &F, nr: IoctlNr) -> c_int {
    libc::ioctl(descriptor.as_raw_descriptor(), nr, 0)
}

/// Run an ioctl with a single value argument.
/// # Safety
/// The caller is responsible for determining the safety of the particular ioctl.
pub unsafe fn ioctl_with_val(descriptor: &dyn AsRawDescriptor, nr: IoctlNr, arg: c_ulong) -> c_int {
    libc::ioctl(descriptor.as_raw_descriptor(), nr, arg)
}

/// Run an ioctl with an immutable reference.
/// # Safety
/// The caller is responsible for determining the safety of the particular ioctl.
pub unsafe fn ioctl_with_ref<T>(descriptor: &dyn AsRawDescriptor, nr: IoctlNr, arg: &T) -> c_int {
    libc::ioctl(
        descriptor.as_raw_descriptor(),
        nr,
        arg as *const T as *const c_void,
    )
}

/// Run an ioctl with a mutable reference.
/// # Safety
/// The caller is responsible for determining the safety of the particular ioctl.
pub unsafe fn ioctl_with_mut_ref<T>(
    descriptor: &dyn AsRawDescriptor,
    nr: IoctlNr,
    arg: &mut T,
) -> c_int {
    libc::ioctl(
        descriptor.as_raw_descriptor(),
        nr,
        arg as *mut T as *mut c_void,
    )
}

/// Run an ioctl with a raw pointer.
/// # Safety
/// The caller is responsible for determining the safety of the particular ioctl.
pub unsafe fn ioctl_with_ptr<T>(
    descriptor: &dyn AsRawDescriptor,
    nr: IoctlNr,
    arg: *const T,
) -> c_int {
    libc::ioctl(descriptor.as_raw_descriptor(), nr, arg as *const c_void)
}

/// Run an ioctl with a mutable raw pointer.
/// # Safety
/// The caller is responsible for determining the safety of the particular ioctl.
pub unsafe fn ioctl_with_mut_ptr<T>(
    descriptor: &dyn AsRawDescriptor,
    nr: IoctlNr,
    arg: *mut T,
) -> c_int {
    libc::ioctl(descriptor.as_raw_descriptor(), nr, arg as *mut c_void)
}
