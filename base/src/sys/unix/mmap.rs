// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Common mmap support shared between Linux and macOS.
//!
//! `MemoryMapping` and `MemoryMappingArena` are defined here so the type is shared
//! across platforms.  Platform-specific constructors and specialty methods live in
//! `sys/linux/mmap.rs` and `sys/macos/mmap.rs` as additional `impl` blocks.

use libc::c_int;
use libc::PROT_READ;
use libc::PROT_WRITE;

use crate::AsRawDescriptor;
use crate::MappedRegion;
use crate::MemoryMapping as CrateMemoryMapping;
use crate::MemoryMappingBuilder;
use crate::MmapError as Error;
use crate::MmapResult as Result;
use crate::Protection;
use crate::SafeDescriptor;

// -------------------------------------------------------------------------
// Protection helpers (used by both Linux and macOS)
// -------------------------------------------------------------------------

impl From<Protection> for c_int {
    #[inline(always)]
    fn from(p: Protection) -> Self {
        let mut value = 0;
        if p.read {
            value |= PROT_READ
        }
        if p.write {
            value |= PROT_WRITE;
        }
        value
    }
}

/// Validates that `offset`..`offset+range_size` lies within the bounds of a memory mapping of
/// `mmap_size` bytes.  Also checks for any overflow.
pub fn validate_includes_range(mmap_size: usize, offset: usize, range_size: usize) -> Result<()> {
    let end_offset = offset
        .checked_add(range_size)
        .ok_or(Error::InvalidAddress)?;
    if end_offset <= mmap_size {
        Ok(())
    } else {
        Err(Error::InvalidAddress)
    }
}

impl dyn MappedRegion {
    /// Calls msync with MS_SYNC on a mapping of `size` bytes starting at `offset` from the start of
    /// the region.  `offset`..`offset+size` must be contained within the `MappedRegion`.
    pub fn msync(&self, offset: usize, size: usize) -> Result<()> {
        validate_includes_range(self.size(), offset, size)?;

        // SAFETY: Safe because the MappedRegion interface ensures our pointer and size are
        // correct, and we've validated that `offset`..`offset+size` is in range.
        let ret = unsafe {
            libc::msync(
                (self.as_ptr() as usize + offset) as *mut libc::c_void,
                size,
                libc::MS_SYNC,
            )
        };
        if ret != -1 {
            Ok(())
        } else {
            Err(Error::SystemCallFailed(crate::errno::Error::last()))
        }
    }

    /// Calls madvise on a mapping of `size` bytes starting at `offset` from the start of
    /// the region.  `offset`..`offset+size` must be contained within the `MappedRegion`.
    pub fn madvise(&self, offset: usize, size: usize, advice: libc::c_int) -> Result<()> {
        validate_includes_range(self.size(), offset, size)?;

        // SAFETY: Safe because the MappedRegion interface ensures our pointer and size are correct,
        // and we've validated that `offset`..`offset+size` is in range.
        let ret = unsafe {
            libc::madvise(
                (self.as_ptr() as usize + offset) as *mut libc::c_void,
                size,
                advice,
            )
        };
        if ret != -1 {
            Ok(())
        } else {
            Err(Error::SystemCallFailed(crate::errno::Error::last()))
        }
    }
}

// -------------------------------------------------------------------------
// MemoryMapping – struct definition and shared interface
//
// Platform-specific constructors (`new_protection`, `from_fd_offset_protection_populate`,
// `new_protection_fixed`, `from_descriptor_offset_protection_fixed`, `try_mmap`) live in
// `sys/linux/mmap.rs` and `sys/macos/mmap.rs`.
// -------------------------------------------------------------------------

/// Wraps an anonymous shared memory mapping in the current process. Provides
/// RAII semantics including munmap when no longer needed.
#[derive(Debug)]
pub struct MemoryMapping {
    pub(crate) addr: *mut u8,
    pub(crate) size: usize,
}

// SAFETY: Send and Sync aren't automatically inherited for the raw address pointer.
// Accessing that pointer is only done through the stateless interface which allows
// the object to be shared by multiple threads without a decrease in safety.
unsafe impl Send for MemoryMapping {}
// SAFETY: See safety comments for impl Send.
unsafe impl Sync for MemoryMapping {}

impl MemoryMapping {
    /// Creates an anonymous shared, read/write mapping of `size` bytes.
    pub fn new(size: usize) -> Result<MemoryMapping> {
        MemoryMapping::new_protection(size, None, Protection::read_write())
    }

    /// Maps the first `size` bytes of the given `fd` as read/write.
    pub fn from_fd(fd: &dyn AsRawDescriptor, size: usize) -> Result<MemoryMapping> {
        MemoryMapping::from_fd_offset(fd, size, 0)
    }

    /// Maps `size` bytes of the given `fd` starting at `offset` as read/write.
    pub fn from_fd_offset(
        fd: &dyn AsRawDescriptor,
        size: usize,
        offset: u64,
    ) -> Result<MemoryMapping> {
        MemoryMapping::from_fd_offset_protection(fd, size, offset, Protection::read_write())
    }

    /// Maps `size` bytes of the given `fd` starting at `offset` with `prot` protection.
    pub fn from_fd_offset_protection(
        fd: &dyn AsRawDescriptor,
        size: usize,
        offset: u64,
        prot: Protection,
    ) -> Result<MemoryMapping> {
        MemoryMapping::from_fd_offset_protection_populate(fd, size, offset, 0, prot, false)
    }

    /// Returns the size of the mapping in bytes.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Returns a pointer to the beginning of the mapping.
    pub fn as_ptr(&self) -> *mut u8 {
        self.addr
    }

    /// Checks that `offset + count` is within the mapping bounds and returns the sum.
    pub(crate) fn range_end(&self, offset: usize, count: usize) -> Result<usize> {
        let mem_end = offset.checked_add(count).ok_or(Error::InvalidAddress)?;
        if mem_end > self.size {
            return Err(Error::InvalidAddress);
        }
        Ok(mem_end)
    }
}

// SAFETY: Safe because the pointer and size point to a memory range owned by this MemoryMapping
// that won't be unmapped until it's Dropped.
unsafe impl MappedRegion for MemoryMapping {
    fn as_ptr(&self) -> *mut u8 {
        self.addr
    }

    fn size(&self) -> usize {
        self.size
    }
}

impl Drop for MemoryMapping {
    fn drop(&mut self) {
        // SAFETY: This is safe because we mmap'd the area at addr ourselves, and nobody else is
        // holding a reference to it.
        unsafe {
            libc::munmap(self.addr as *mut libc::c_void, self.size);
        }
    }
}

// -------------------------------------------------------------------------
// MemoryMappingArena – struct definition and shared interface
//
// Platform-specific constructors (`new`, `add_fd_offset_protection`, `remove`) live in
// `sys/linux/mmap.rs` and `sys/macos/mmap.rs`.
// -------------------------------------------------------------------------

/// Tracks fixed memory maps within an anonymous memory-mapped fixed-sized arena
/// in the current process.
pub struct MemoryMappingArena {
    pub(crate) addr: *mut u8,
    pub(crate) size: usize,
}

// SAFETY: Send and Sync aren't automatically inherited for the raw address pointer.
// Accessing that pointer is only done through the stateless interface which allows
// the object to be shared by multiple threads without a decrease in safety.
unsafe impl Send for MemoryMappingArena {}
// SAFETY: See safety comments for impl Send.
unsafe impl Sync for MemoryMappingArena {}

impl MemoryMappingArena {
    /// Returns a pointer to the start of the arena.
    pub fn as_ptr(&self) -> *mut u8 {
        self.addr
    }

    /// Returns the size of the arena in bytes.
    pub fn size(&self) -> usize {
        self.size
    }
}

// SAFETY: Safe because the pointer and size point to a memory range owned by this
// MemoryMappingArena that won't be unmapped until it's Dropped.
unsafe impl MappedRegion for MemoryMappingArena {
    fn as_ptr(&self) -> *mut u8 {
        self.addr
    }

    fn size(&self) -> usize {
        self.size
    }

    fn add_fd_mapping(
        &mut self,
        offset: usize,
        size: usize,
        fd: &dyn AsRawDescriptor,
        fd_offset: u64,
        prot: crate::Protection,
    ) -> Result<()> {
        self.add_fd_offset_protection(offset, size, fd, fd_offset, prot)
    }

    fn remove_mapping(&mut self, offset: usize, size: usize) -> Result<()> {
        self.remove(offset, size)
    }
}

impl Drop for MemoryMappingArena {
    fn drop(&mut self) {
        // SAFETY: We own this mapping; nobody else holds a reference to it.
        unsafe {
            libc::munmap(self.addr as *mut libc::c_void, self.size);
        }
    }
}

// -------------------------------------------------------------------------
// MemoryMappingBuilder – shared Unix builder
// -------------------------------------------------------------------------

pub trait MemoryMappingBuilderUnix<'a> {
    fn from_file(self, file: &'a std::fs::File) -> MemoryMappingBuilder<'a>;
    #[allow(clippy::wrong_self_convention)]
    fn from_descriptor(self, descriptor: &'a dyn AsRawDescriptor) -> MemoryMappingBuilder<'a>;
}

impl<'a> MemoryMappingBuilderUnix<'a> for MemoryMappingBuilder<'a> {
    fn from_file(mut self, file: &'a std::fs::File) -> MemoryMappingBuilder<'a> {
        self.descriptor = Some(file as &dyn AsRawDescriptor);
        self
    }

    #[allow(clippy::wrong_self_convention)]
    fn from_descriptor(mut self, descriptor: &'a dyn AsRawDescriptor) -> MemoryMappingBuilder<'a> {
        self.descriptor = Some(descriptor);
        self
    }
}

impl<'a> MemoryMappingBuilder<'a> {
    pub fn build(self) -> Result<CrateMemoryMapping> {
        match self.descriptor {
            None => MemoryMappingBuilder::wrap(
                MemoryMapping::new_protection(
                    self.size,
                    self.align,
                    self.protection.unwrap_or_else(Protection::read_write),
                )?,
                None,
            ),
            Some(descriptor) => MemoryMappingBuilder::wrap(
                MemoryMapping::from_fd_offset_protection_populate(
                    descriptor,
                    self.size,
                    self.offset.unwrap_or(0),
                    self.align.unwrap_or(0),
                    self.protection.unwrap_or_else(Protection::read_write),
                    false,
                )?,
                None,
            ),
        }
    }

    pub(crate) fn wrap(
        mapping: MemoryMapping,
        file_descriptor: Option<&'a dyn AsRawDescriptor>,
    ) -> Result<CrateMemoryMapping> {
        let file_descriptor = match file_descriptor {
            Some(descriptor) => Some(
                SafeDescriptor::try_from(descriptor)
                    .map_err(|_| Error::SystemCallFailed(crate::errno::Error::last()))?,
            ),
            None => None,
        };
        Ok(CrateMemoryMapping {
            mapping,
            _file_descriptor: file_descriptor,
        })
    }
}
