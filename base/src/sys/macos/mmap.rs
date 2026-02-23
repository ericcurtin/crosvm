// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! macOS-specific MemoryMapping constructors and methods.
//!
//! The struct definitions live in `sys/unix/mmap.rs`; this file adds macOS-specific
//! `impl` blocks on top of those shared definitions.

use std::ptr::null_mut;

use libc::c_int;

use crate::errno::Error as ErrnoError;
// Re-export the shared types so callers can import them from macos::mmap.
pub use crate::sys::unix::mmap::MemoryMapping;
pub use crate::sys::unix::mmap::MemoryMappingArena;
pub use crate::sys::unix::mmap::MemoryMappingBuilderUnix;
use crate::AsRawDescriptor;
use crate::MmapError as Error;
use crate::MmapResult as Result;
use crate::Protection;
use crate::RawDescriptor;

// -------------------------------------------------------------------------
// MemoryMapping – macOS-specific constructors and methods
// -------------------------------------------------------------------------

impl MemoryMapping {
    /// Creates an anonymous shared mapping of `size` bytes with `prot` protection.
    pub fn new_protection(
        size: usize,
        align: Option<u64>,
        prot: Protection,
    ) -> Result<MemoryMapping> {
        unsafe { MemoryMapping::try_mmap(None, size, align, prot.into(), None) }
    }

    /// Maps `size` bytes starting at `offset` from `fd` with optional alignment and protection.
    /// The `populate` flag is ignored on macOS (no MAP_POPULATE equivalent).
    pub fn from_fd_offset_protection_populate(
        fd: &dyn AsRawDescriptor,
        size: usize,
        offset: u64,
        align: u64,
        prot: Protection,
        _populate: bool,
    ) -> Result<MemoryMapping> {
        unsafe {
            MemoryMapping::try_mmap(
                None,
                size,
                if align > 0 { Some(align) } else { None },
                prot.into(),
                Some((fd.as_raw_descriptor(), offset)),
            )
        }
    }

    /// Creates an anonymous shared mapping at a fixed address.
    ///
    /// # Safety
    /// The caller must ensure `(addr..addr+size)` is not already mapped.
    pub unsafe fn new_protection_fixed(
        addr: *mut u8,
        size: usize,
        prot: Protection,
    ) -> Result<MemoryMapping> {
        MemoryMapping::try_mmap(Some(addr), size, None, prot.into(), None)
    }

    /// Maps `size` bytes from `fd` at a fixed address.
    ///
    /// # Safety
    /// The caller must ensure `(addr..addr+size)` is not already mapped.
    pub unsafe fn from_descriptor_offset_protection_fixed(
        addr: *mut u8,
        fd: &dyn AsRawDescriptor,
        size: usize,
        offset: u64,
        prot: Protection,
    ) -> Result<MemoryMapping> {
        MemoryMapping::try_mmap(
            Some(addr),
            size,
            None,
            prot.into(),
            Some((fd.as_raw_descriptor(), offset)),
        )
    }

    /// Core mmap wrapper for macOS.  Handles optional alignment via a reserve-then-remap approach.
    unsafe fn try_mmap(
        addr: Option<*mut u8>,
        size: usize,
        align: Option<u64>,
        prot: c_int,
        fd: Option<(RawDescriptor, u64)>,
    ) -> Result<MemoryMapping> {
        let (raw_fd, offset) = fd.unwrap_or((-1, 0));
        let has_fd = fd.is_some();

        if let Some(alignment) = align.filter(|&a| a > 0) {
            let alignment = alignment as usize;

            // Step 1: Reserve address space with an anonymous PROT_NONE mapping.
            let reserve = libc::mmap(
                addr.map_or(null_mut(), |a| a as *mut libc::c_void),
                size + alignment,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            if reserve == libc::MAP_FAILED {
                return Err(Error::SystemCallFailed(ErrnoError::last()));
            }

            // Step 2: Compute the aligned address within the reserved region.
            let aligned = (reserve as usize + alignment - 1) & !(alignment - 1);

            // Step 3: Map actual content at the aligned address with MAP_FIXED.
            let mut flags = libc::MAP_SHARED | libc::MAP_FIXED;
            if !has_fd {
                flags |= libc::MAP_ANONYMOUS;
            }
            let mapped = libc::mmap(
                aligned as *mut libc::c_void,
                size,
                prot,
                flags,
                raw_fd,
                offset as libc::off_t,
            );
            if mapped == libc::MAP_FAILED {
                libc::munmap(reserve, size + alignment);
                return Err(Error::SystemCallFailed(ErrnoError::last()));
            }

            // Step 4: Unmap the unused prefix and suffix of the reserved region.
            let prefix_size = aligned - reserve as usize;
            if prefix_size > 0 {
                libc::munmap(reserve, prefix_size);
            }
            let suffix_size = alignment - prefix_size;
            if suffix_size > 0 {
                libc::munmap((aligned + size) as *mut libc::c_void, suffix_size);
            }

            Ok(MemoryMapping {
                addr: aligned as *mut u8,
                size,
            })
        } else {
            // No alignment required – simple mmap.
            let mut flags = libc::MAP_SHARED;
            if !has_fd {
                flags |= libc::MAP_ANONYMOUS;
            }
            let mapped = libc::mmap(
                addr.map_or(null_mut(), |a| a as *mut libc::c_void),
                size,
                prot,
                flags,
                raw_fd,
                offset as libc::off_t,
            );
            if mapped == libc::MAP_FAILED {
                return Err(Error::SystemCallFailed(ErrnoError::last()));
            }
            Ok(MemoryMapping {
                addr: mapped as *mut u8,
                size,
            })
        }
    }

    /// Calls msync with MS_SYNC on the whole mapping.
    pub fn msync(&self) -> Result<()> {
        let ret = unsafe { libc::msync(self.addr as *mut libc::c_void, self.size, libc::MS_SYNC) };
        if ret != -1 {
            Ok(())
        } else {
            Err(Error::SystemCallFailed(ErrnoError::last()))
        }
    }
}

// -------------------------------------------------------------------------
// MemoryMappingArena – macOS-specific constructors and methods
// -------------------------------------------------------------------------

impl MemoryMappingArena {
    /// Creates an mmap arena of `size` bytes backed by anonymous memory.
    pub fn new(size: usize) -> Result<MemoryMappingArena> {
        // SAFETY: mmap with MAP_ANON|MAP_PRIVATE creates a new anonymous mapping.
        let addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_NONE,
                libc::MAP_ANON | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        if addr == libc::MAP_FAILED {
            return Err(Error::SystemCallFailed(ErrnoError::last()));
        }
        Ok(MemoryMappingArena {
            addr: addr as *mut u8,
            size,
        })
    }

    /// Maps `size` bytes starting at `fd_offset` in `fd` at `offset` in the arena with `prot`.
    pub fn add_fd_offset_protection(
        &mut self,
        offset: usize,
        size: usize,
        fd: &dyn AsRawDescriptor,
        fd_offset: u64,
        prot: crate::Protection,
    ) -> Result<()> {
        let prot_flags: libc::c_int = prot.into();
        // SAFETY: Remapping within our owned arena range.
        let addr = unsafe {
            libc::mmap(
                (self.addr as usize + offset) as *mut libc::c_void,
                size,
                prot_flags,
                libc::MAP_SHARED | libc::MAP_FIXED,
                fd.as_raw_descriptor(),
                fd_offset as libc::off_t,
            )
        };
        if addr == libc::MAP_FAILED {
            return Err(Error::SystemCallFailed(ErrnoError::last()));
        }
        Ok(())
    }

    /// Removes a mapping at `offset` of `size` bytes, replacing with a PROT_NONE anonymous mapping.
    pub fn remove(&mut self, offset: usize, size: usize) -> Result<()> {
        // SAFETY: Remapping within our owned arena range.
        let addr = unsafe {
            libc::mmap(
                (self.addr as usize + offset) as *mut libc::c_void,
                size,
                libc::PROT_NONE,
                libc::MAP_ANON | libc::MAP_PRIVATE | libc::MAP_FIXED,
                -1,
                0,
            )
        };
        if addr == libc::MAP_FAILED {
            return Err(Error::SystemCallFailed(ErrnoError::last()));
        }
        Ok(())
    }
}
