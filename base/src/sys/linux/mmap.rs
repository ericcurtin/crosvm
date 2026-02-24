// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Linux-specific MemoryMapping constructors and specialty methods.
//!
//! The struct definitions live in `sys/unix/mmap.rs`; this file adds Linux-specific
//! `impl` blocks on top of those shared definitions.

use std::ptr::null_mut;

use libc::c_int;
use log::warn;

use super::Error as ErrnoError;
use crate::pagesize;
use crate::sys::unix::mmap::validate_includes_range;
// Re-export the shared types so callers can import them from linux::mmap.
pub use crate::sys::unix::mmap::MemoryMapping;
pub use crate::sys::unix::mmap::MemoryMappingArena;
pub use crate::sys::unix::mmap::MemoryMappingBuilderUnix;
use crate::AsRawDescriptor;
use crate::Descriptor;
use crate::MemoryMapping as CrateMemoryMapping;
use crate::MemoryMappingBuilder;
use crate::MmapError as Error;
use crate::MmapResult as Result;
use crate::Protection;
use crate::RawDescriptor;

// -------------------------------------------------------------------------
// MemoryMapping – Linux-specific constructors and specialty methods
// -------------------------------------------------------------------------

impl MemoryMapping {
    /// Creates an anonymous shared mapping of `size` bytes with `prot` protection.
    ///
    /// * `size`  - Size of memory region in bytes.
    /// * `align` - Optional alignment for the mapping address.
    /// * `prot`  - Protection (e.g. readable/writable) of the memory region.
    pub fn new_protection(
        size: usize,
        align: Option<u64>,
        prot: Protection,
    ) -> Result<MemoryMapping> {
        // SAFETY: Creating an anonymous mapping in a place not already used by any other area.
        unsafe { MemoryMapping::try_mmap(None, size, align, prot.into(), None) }
    }

    /// Maps `size` bytes starting at `offset` from `fd` with optional alignment, protection,
    /// and MAP_POPULATE pre-faulting.
    pub fn from_fd_offset_protection_populate(
        fd: &dyn AsRawDescriptor,
        size: usize,
        offset: u64,
        align: u64,
        prot: Protection,
        populate: bool,
    ) -> Result<MemoryMapping> {
        // SAFETY: Creating a mapping in a place not already used by any other area.
        unsafe {
            MemoryMapping::try_mmap_populate(
                None,
                size,
                Some(align),
                prot.into(),
                Some((fd, offset)),
                populate,
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
        MemoryMapping::try_mmap(Some(addr), size, None, prot.into(), Some((fd, offset)))
    }

    /// Helper: calls try_mmap_populate without MAP_POPULATE.
    unsafe fn try_mmap(
        addr: Option<*mut u8>,
        size: usize,
        align: Option<u64>,
        prot: c_int,
        fd: Option<(&dyn AsRawDescriptor, u64)>,
    ) -> Result<MemoryMapping> {
        MemoryMapping::try_mmap_populate(addr, size, align, prot, fd, false)
    }

    /// Core mmap wrapper. Handles alignment, MAP_POPULATE, and fd seals.
    unsafe fn try_mmap_populate(
        addr: Option<*mut u8>,
        size: usize,
        align: Option<u64>,
        prot: c_int,
        fd: Option<(&dyn AsRawDescriptor, u64)>,
        populate: bool,
    ) -> Result<MemoryMapping> {
        let mut flags = libc::MAP_SHARED;
        if populate {
            flags |= libc::MAP_POPULATE;
        }
        let addr = match addr {
            Some(addr) => {
                if (addr as usize) % pagesize() != 0 {
                    return Err(Error::NotPageAligned);
                }
                flags |= libc::MAP_FIXED | libc::MAP_NORESERVE;
                addr as *mut libc::c_void
            }
            None => null_mut(),
        };

        let align = if align.unwrap_or(0) == pagesize() as u64 {
            Some(0)
        } else {
            align
        };

        let (addr, orig_addr, orig_size) = match align {
            None | Some(0) => (addr, None, None),
            Some(align) => {
                if !addr.is_null() || !align.is_power_of_two() {
                    return Err(Error::InvalidAlignment);
                }
                let orig_size = size + align as usize;
                let orig_addr = libc::mmap64(
                    null_mut(),
                    orig_size,
                    prot,
                    libc::MAP_PRIVATE | libc::MAP_NORESERVE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                );
                if orig_addr == libc::MAP_FAILED {
                    return Err(Error::SystemCallFailed(ErrnoError::last()));
                }
                flags |= libc::MAP_FIXED;
                let mask = align - 1;
                (
                    (orig_addr.wrapping_add(mask as usize) as u64 & !mask) as *mut libc::c_void,
                    Some(orig_addr),
                    Some(orig_size),
                )
            }
        };

        let (fd, offset) = match fd {
            Some((fd, offset)) => {
                if offset > libc::off64_t::MAX as u64 {
                    return Err(Error::InvalidOffset);
                }
                // SAFETY: No third parameter expected; return value checked.
                let seals = unsafe { libc::fcntl(fd.as_raw_descriptor(), libc::F_GET_SEALS) };
                if (seals >= 0) && (seals & libc::F_SEAL_WRITE != 0) {
                    flags &= !libc::MAP_SHARED;
                    flags |= libc::MAP_PRIVATE;
                }
                (fd.as_raw_descriptor(), offset as libc::off64_t)
            }
            None => {
                flags |= libc::MAP_ANONYMOUS | libc::MAP_NORESERVE;
                (-1, 0)
            }
        };
        let addr = libc::mmap64(addr, size, prot, flags, fd, offset);
        if addr == libc::MAP_FAILED {
            return Err(Error::SystemCallFailed(ErrnoError::last()));
        }

        if let Some(orig_addr) = orig_addr {
            let unmap_start = orig_addr as usize;
            let unmap_end = addr as usize;
            let unmap_size = unmap_end - unmap_start;
            if unmap_size > 0 {
                libc::munmap(orig_addr, unmap_size);
            }
            let unmap_start = addr as usize + size;
            let unmap_end = orig_addr as usize + orig_size.unwrap();
            let unmap_size = unmap_end - unmap_start;
            if unmap_size > 0 {
                libc::munmap(unmap_start as *mut libc::c_void, unmap_size);
            }
        }

        let _ = libc::madvise(addr, size, libc::MADV_DONTDUMP);
        let _ = libc::madvise(addr, size, libc::MADV_MERGEABLE);

        Ok(MemoryMapping {
            addr: addr as *mut u8,
            size,
        })
    }

    // -----------------------------------------------------------------------
    // Linux-only specialty methods
    // -----------------------------------------------------------------------

    /// Madvise the kernel to unmap on fork.
    pub fn use_dontfork(&self) -> Result<()> {
        let ret = unsafe {
            libc::madvise(
                self.as_ptr() as *mut libc::c_void,
                self.size(),
                libc::MADV_DONTFORK,
            )
        };
        if ret == -1 {
            Err(Error::SystemCallFailed(ErrnoError::last()))
        } else {
            Ok(())
        }
    }

    /// Madvise the kernel to use Huge Pages for this mapping.
    pub fn use_hugepages(&self) -> Result<()> {
        const SZ_2M: usize = 2 * 1024 * 1024;
        if self.size() < SZ_2M {
            return Ok(());
        }
        let ret = unsafe {
            libc::madvise(
                self.as_ptr() as *mut libc::c_void,
                self.size(),
                libc::MADV_HUGEPAGE,
            )
        };
        if ret == -1 {
            Err(Error::SystemCallFailed(ErrnoError::last()))
        } else {
            Ok(())
        }
    }

    /// Calls msync with MS_SYNC on the whole mapping.
    pub fn msync(&self) -> Result<()> {
        let ret = unsafe {
            libc::msync(
                self.as_ptr() as *mut libc::c_void,
                self.size(),
                libc::MS_SYNC,
            )
        };
        if ret == -1 {
            return Err(Error::SystemCallFailed(ErrnoError::last()));
        }
        Ok(())
    }

    /// Uses madvise MADV_REMOVE to zero-out the range. Subsequent reads return zero bytes.
    pub fn remove_range(&self, mem_offset: usize, count: usize) -> Result<()> {
        self.range_end(mem_offset, count)
            .map_err(|_| Error::InvalidRange(mem_offset, count, self.size()))?;
        // SAFETY: All args to madvise are valid; return value is checked.
        let ret = unsafe {
            libc::madvise(
                (self.addr as usize + mem_offset) as *mut _,
                count,
                libc::MADV_REMOVE,
            )
        };
        if ret < 0 {
            Err(Error::SystemCallFailed(super::Error::last()))
        } else {
            Ok(())
        }
    }

    /// Tell the kernel to readahead the range (non-blocking).
    pub fn async_prefetch(&self, mem_offset: usize, count: usize) -> Result<()> {
        self.range_end(mem_offset, count)
            .map_err(|_| Error::InvalidRange(mem_offset, count, self.size()))?;
        // SAFETY: Populating pages from the backing file does not affect Rust memory safety.
        let ret = unsafe {
            libc::madvise(
                (self.addr as usize + mem_offset) as *mut _,
                count,
                libc::MADV_WILLNEED,
            )
        };
        if ret < 0 {
            Err(Error::SystemCallFailed(super::Error::last()))
        } else {
            Ok(())
        }
    }

    /// Tell the kernel to drop the page cache for the range.
    pub fn drop_page_cache(&self, mem_offset: usize, count: usize) -> Result<()> {
        self.range_end(mem_offset, count)
            .map_err(|_| Error::InvalidRange(mem_offset, count, self.size()))?;
        // SAFETY: Dropping the page cache does not affect Rust memory safety.
        let ret = unsafe {
            libc::madvise(
                (self.addr as usize + mem_offset) as *mut _,
                count,
                libc::MADV_DONTNEED,
            )
        };
        if ret < 0 {
            Err(Error::SystemCallFailed(super::Error::last()))
        } else {
            Ok(())
        }
    }

    /// Lock the resident pages in the range not to be swapped out.
    pub fn lock_on_fault(&self, mem_offset: usize, count: usize) -> Result<()> {
        self.range_end(mem_offset, count)
            .map_err(|_| Error::InvalidRange(mem_offset, count, self.size()))?;
        let addr = self.addr as usize + mem_offset;
        // SAFETY: MLOCK_ONFAULT only affects swap behavior, no impact on Rust semantics.
        let ret = unsafe { libc::mlock2(addr as *mut _, count, libc::MLOCK_ONFAULT) };
        if ret < 0 {
            let errno = super::Error::last();
            warn!(
                "failed to mlock at {:#x} with length {}: {}",
                addr as u64,
                self.size(),
                errno,
            );
            Err(Error::SystemCallFailed(errno))
        } else {
            Ok(())
        }
    }

    /// Unlock the range of pages.
    pub fn unlock(&self, mem_offset: usize, count: usize) -> Result<()> {
        self.range_end(mem_offset, count)
            .map_err(|_| Error::InvalidRange(mem_offset, count, self.size()))?;
        // SAFETY: munlock(2) does not affect Rust memory safety.
        let ret = unsafe { libc::munlock((self.addr as usize + mem_offset) as *mut _, count) };
        if ret < 0 {
            Err(Error::SystemCallFailed(super::Error::last()))
        } else {
            Ok(())
        }
    }
}

// -------------------------------------------------------------------------
// MemoryMappingArena – Linux-specific constructors and methods
// -------------------------------------------------------------------------

impl MemoryMappingArena {
    /// Creates an mmap arena of `size` bytes.
    pub fn new(size: usize) -> Result<MemoryMappingArena> {
        // Reserve the arena using an anonymous read-only mmap.
        MemoryMapping::new_protection(size, None, Protection::read()).map(From::from)
    }

    /// Anonymously maps `size` bytes at `offset` with `prot` protections.
    pub fn add_anon_protection(
        &mut self,
        offset: usize,
        size: usize,
        prot: Protection,
    ) -> Result<()> {
        self.try_add(offset, size, prot, None)
    }

    /// Anonymously maps `size` bytes at `offset` with read/write protection.
    pub fn add_anon(&mut self, offset: usize, size: usize) -> Result<()> {
        self.add_anon_protection(offset, size, Protection::read_write())
    }

    /// Maps `size` bytes from the start of `fd` at `offset` in the arena.
    pub fn add_fd(&mut self, offset: usize, size: usize, fd: &dyn AsRawDescriptor) -> Result<()> {
        self.add_fd_offset(offset, size, fd, 0)
    }

    /// Maps `size` bytes starting at `fd_offset` in `fd` at `offset` in the arena.
    pub fn add_fd_offset(
        &mut self,
        offset: usize,
        size: usize,
        fd: &dyn AsRawDescriptor,
        fd_offset: u64,
    ) -> Result<()> {
        self.add_fd_offset_protection(offset, size, fd, fd_offset, Protection::read_write())
    }

    /// Maps `size` bytes starting at `fd_offset` in `fd` at `offset` in the arena with `prot`.
    pub fn add_fd_offset_protection(
        &mut self,
        offset: usize,
        size: usize,
        fd: &dyn AsRawDescriptor,
        fd_offset: u64,
        prot: Protection,
    ) -> Result<()> {
        self.try_add(offset, size, prot, Some((fd, fd_offset)))
    }

    /// Internal helper: maps at a fixed address within the arena using MemoryMapping constructors.
    fn try_add(
        &mut self,
        offset: usize,
        size: usize,
        prot: Protection,
        fd: Option<(&dyn AsRawDescriptor, u64)>,
    ) -> Result<()> {
        if offset % pagesize() != 0 {
            return Err(Error::NotPageAligned);
        }
        validate_includes_range(self.size(), offset, size)?;

        // SAFETY: The range has been validated to lie within our owned arena.
        let mmap = unsafe {
            match fd {
                Some((fd, fd_offset)) => MemoryMapping::from_descriptor_offset_protection_fixed(
                    self.addr.add(offset),
                    fd,
                    size,
                    fd_offset,
                    prot,
                )?,
                None => MemoryMapping::new_protection_fixed(self.addr.add(offset), size, prot)?,
            }
        };
        // The arena owns the address space; prevent the MemoryMapping from unmapping it.
        std::mem::forget(mmap);
        Ok(())
    }

    /// Removes `size` bytes at `offset`, replacing with a read-only anonymous mapping.
    pub fn remove(&mut self, offset: usize, size: usize) -> Result<()> {
        self.try_add(offset, size, Protection::read(), None)
    }
}

impl From<MemoryMapping> for MemoryMappingArena {
    fn from(mmap: MemoryMapping) -> Self {
        let addr = mmap.as_ptr();
        let size = mmap.size();
        // Transfer ownership to the arena; MemoryMappingArena will call munmap on drop.
        std::mem::forget(mmap);
        MemoryMappingArena { addr, size }
    }
}

impl From<CrateMemoryMapping> for MemoryMappingArena {
    fn from(mmap: CrateMemoryMapping) -> Self {
        MemoryMappingArena::from(mmap.mapping)
    }
}
