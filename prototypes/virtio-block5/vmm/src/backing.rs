//! Backing store implementations for virtio-block devices.
//!
//! Provides different I/O strategies:
//! - Regular file I/O (read/write syscalls)
//! - O_DIRECT (bypass page cache)
//! - Memory-mapped files (mmap)

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;

use memmap2::{MmapMut, MmapOptions};

/// Alignment required for O_DIRECT I/O (typically 512 or 4096 bytes).
const DIRECT_IO_ALIGNMENT: usize = 4096;

/// Backing store mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackingMode {
    /// Regular buffered file I/O
    Regular,
    /// Direct I/O bypassing page cache (O_DIRECT)
    Direct,
    /// Memory-mapped file access
    Mmap,
}

impl std::fmt::Display for BackingMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackingMode::Regular => write!(f, "regular"),
            BackingMode::Direct => write!(f, "O_DIRECT"),
            BackingMode::Mmap => write!(f, "mmap"),
        }
    }
}

/// A backing store that can use different I/O strategies.
pub enum BackingStore {
    /// Regular file with buffered I/O
    Regular(RegularBacking),
    /// File with O_DIRECT for direct I/O
    Direct(DirectBacking),
    /// Memory-mapped file
    Mmap(MmapBacking),
}

impl BackingStore {
    /// Open a backing store with the specified mode.
    pub fn open(
        path: &Path,
        read_only: bool,
        mode: BackingMode,
        size: Option<u64>,
    ) -> io::Result<Self> {
        match mode {
            BackingMode::Regular => {
                let backing = RegularBacking::open(path, read_only, size)?;
                Ok(BackingStore::Regular(backing))
            }
            BackingMode::Direct => {
                let backing = DirectBacking::open(path, read_only, size)?;
                Ok(BackingStore::Direct(backing))
            }
            BackingMode::Mmap => {
                let backing = MmapBacking::open(path, read_only, size)?;
                Ok(BackingStore::Mmap(backing))
            }
        }
    }

    /// Read data from the backing store at the given offset.
    pub fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        match self {
            BackingStore::Regular(b) => b.read_at(offset, buf),
            BackingStore::Direct(b) => b.read_at(offset, buf),
            BackingStore::Mmap(b) => b.read_at(offset, buf),
        }
    }

    /// Write data to the backing store at the given offset.
    pub fn write_at(&mut self, offset: u64, buf: &[u8]) -> io::Result<()> {
        match self {
            BackingStore::Regular(b) => b.write_at(offset, buf),
            BackingStore::Direct(b) => b.write_at(offset, buf),
            BackingStore::Mmap(b) => b.write_at(offset, buf),
        }
    }

    /// Sync data to disk.
    pub fn sync(&self) -> io::Result<()> {
        match self {
            BackingStore::Regular(b) => b.sync(),
            BackingStore::Direct(b) => b.sync(),
            BackingStore::Mmap(b) => b.sync(),
        }
    }

    /// Get the size of the backing store.
    #[allow(dead_code)]
    pub fn size(&self) -> u64 {
        match self {
            BackingStore::Regular(b) => b.size,
            BackingStore::Direct(b) => b.size,
            BackingStore::Mmap(b) => b.size,
        }
    }

    /// Get the backing mode.
    #[allow(dead_code)]
    pub fn mode(&self) -> BackingMode {
        match self {
            BackingStore::Regular(_) => BackingMode::Regular,
            BackingStore::Direct(_) => BackingMode::Direct,
            BackingStore::Mmap(_) => BackingMode::Mmap,
        }
    }
}

/// Regular buffered file I/O backing.
pub struct RegularBacking {
    file: File,
    #[allow(dead_code)]
    size: u64,
}

impl RegularBacking {
    /// Open a file with regular buffered I/O.
    pub fn open(path: &Path, read_only: bool, preallocate: Option<u64>) -> io::Result<Self> {
        let file = if read_only {
            File::open(path)?
        } else {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(path)?
        };

        let size = if let Some(s) = preallocate {
            if !read_only {
                file.set_len(s)?;
            }
            s
        } else {
            file.metadata()?.len()
        };

        Ok(Self { file, size })
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.read_exact(buf)
    }

    fn write_at(&mut self, offset: u64, buf: &[u8]) -> io::Result<()> {
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(buf)
    }

    fn sync(&self) -> io::Result<()> {
        self.file.sync_all()
    }
}

/// Direct I/O backing using O_DIRECT.
pub struct DirectBacking {
    file: File,
    #[allow(dead_code)]
    size: u64,
    /// Aligned buffer for O_DIRECT operations
    aligned_buf: Vec<u8>,
}

impl DirectBacking {
    /// Open a file with O_DIRECT for direct I/O.
    pub fn open(path: &Path, read_only: bool, preallocate: Option<u64>) -> io::Result<Self> {
        let file = if read_only {
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECT)
                .open(path)?
        } else {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .custom_flags(libc::O_DIRECT)
                .open(path)?
        };

        let size = if let Some(s) = preallocate {
            if !read_only {
                // For O_DIRECT, we need to pre-allocate with fallocate
                // Fall back to ftruncate if fallocate fails
                let fd = file.as_raw_fd();
                let ret = unsafe { libc::fallocate(fd, 0, 0, s as libc::off_t) };
                if ret != 0 {
                    // fallocate not supported, use ftruncate
                    file.set_len(s)?;
                }
            }
            s
        } else {
            file.metadata()?.len()
        };

        // Pre-allocate an aligned buffer for I/O
        // We'll resize as needed, but start with a reasonable size
        let aligned_buf = Self::allocate_aligned(DIRECT_IO_ALIGNMENT);

        Ok(Self {
            file,
            size,
            aligned_buf,
        })
    }

    /// Allocate a buffer aligned to DIRECT_IO_ALIGNMENT.
    fn allocate_aligned(size: usize) -> Vec<u8> {
        // Round up size to alignment
        let aligned_size = (size + DIRECT_IO_ALIGNMENT - 1) & !(DIRECT_IO_ALIGNMENT - 1);

        // Use posix_memalign for proper alignment
        let mut ptr: *mut libc::c_void = std::ptr::null_mut();
        let ret =
            unsafe { libc::posix_memalign(&mut ptr, DIRECT_IO_ALIGNMENT, aligned_size.max(1)) };

        if ret != 0 || ptr.is_null() {
            // Fall back to regular allocation (won't work with O_DIRECT)
            return vec![0u8; aligned_size];
        }

        // SAFETY: posix_memalign succeeded, ptr is valid and properly aligned
        unsafe {
            let slice = std::slice::from_raw_parts_mut(ptr as *mut u8, aligned_size);
            slice.fill(0);
            Vec::from_raw_parts(ptr as *mut u8, aligned_size, aligned_size)
        }
    }

    fn ensure_buffer_size(&mut self, size: usize) {
        let aligned_size = (size + DIRECT_IO_ALIGNMENT - 1) & !(DIRECT_IO_ALIGNMENT - 1);
        if self.aligned_buf.len() < aligned_size {
            self.aligned_buf = Self::allocate_aligned(aligned_size);
        }
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        // O_DIRECT requires aligned offset, length, and buffer
        let aligned_offset = offset & !(DIRECT_IO_ALIGNMENT as u64 - 1);
        let offset_in_block = (offset - aligned_offset) as usize;
        let read_len =
            (offset_in_block + buf.len() + DIRECT_IO_ALIGNMENT - 1) & !(DIRECT_IO_ALIGNMENT - 1);

        self.ensure_buffer_size(read_len);
        self.file.seek(SeekFrom::Start(aligned_offset))?;

        let bytes_read = self.file.read(&mut self.aligned_buf[..read_len])?;
        if bytes_read < offset_in_block + buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "short read with O_DIRECT",
            ));
        }

        buf.copy_from_slice(&self.aligned_buf[offset_in_block..offset_in_block + buf.len()]);
        Ok(())
    }

    fn write_at(&mut self, offset: u64, buf: &[u8]) -> io::Result<()> {
        // O_DIRECT requires aligned offset, length, and buffer
        let aligned_offset = offset & !(DIRECT_IO_ALIGNMENT as u64 - 1);
        let offset_in_block = (offset - aligned_offset) as usize;
        let write_len =
            (offset_in_block + buf.len() + DIRECT_IO_ALIGNMENT - 1) & !(DIRECT_IO_ALIGNMENT - 1);

        self.ensure_buffer_size(write_len);

        // If not aligned, we need to read-modify-write
        if offset_in_block != 0 || !buf.len().is_multiple_of(DIRECT_IO_ALIGNMENT) {
            self.file.seek(SeekFrom::Start(aligned_offset))?;
            // Read existing data first (to preserve unwritten portions)
            let _ = self.file.read(&mut self.aligned_buf[..write_len]);
        }

        // Copy new data into aligned buffer
        self.aligned_buf[offset_in_block..offset_in_block + buf.len()].copy_from_slice(buf);

        // Write aligned data
        self.file.seek(SeekFrom::Start(aligned_offset))?;
        self.file.write_all(&self.aligned_buf[..write_len])
    }

    fn sync(&self) -> io::Result<()> {
        self.file.sync_all()
    }
}

/// Memory-mapped file backing.
pub struct MmapBacking {
    mmap: MmapMut,
    #[allow(dead_code)]
    size: u64,
}

impl MmapBacking {
    /// Open a file with memory mapping.
    pub fn open(path: &Path, read_only: bool, preallocate: Option<u64>) -> io::Result<Self> {
        let file = if read_only {
            File::open(path)?
        } else {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(path)?
        };

        let size = if let Some(s) = preallocate {
            if !read_only {
                file.set_len(s)?;
            }
            s
        } else {
            file.metadata()?.len()
        };

        if size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot mmap zero-length file",
            ));
        }

        // SAFETY: We have exclusive access to this file and it's sized appropriately
        let mmap = unsafe { MmapOptions::new().len(size as usize).map_mut(&file)? };

        Ok(Self { mmap, size })
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let start = offset as usize;
        let end = start + buf.len();

        if end > self.mmap.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "read beyond mmap end",
            ));
        }

        buf.copy_from_slice(&self.mmap[start..end]);
        Ok(())
    }

    fn write_at(&mut self, offset: u64, buf: &[u8]) -> io::Result<()> {
        let start = offset as usize;
        let end = start + buf.len();

        if end > self.mmap.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "write beyond mmap end",
            ));
        }

        self.mmap[start..end].copy_from_slice(buf);
        Ok(())
    }

    fn sync(&self) -> io::Result<()> {
        self.mmap.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_regular_backing() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&[0u8; 4096]).unwrap();
        tmp.flush().unwrap();

        let mut backing =
            BackingStore::open(tmp.path(), false, BackingMode::Regular, Some(4096)).unwrap();
        assert_eq!(backing.mode(), BackingMode::Regular);
        assert_eq!(backing.size(), 4096);

        // Write and read back
        backing.write_at(0, &[1, 2, 3, 4]).unwrap();
        let mut buf = [0u8; 4];
        backing.read_at(0, &mut buf).unwrap();
        assert_eq!(buf, [1, 2, 3, 4]);
    }

    #[test]
    fn test_mmap_backing() {
        let tmp = NamedTempFile::new().unwrap();

        let mut backing =
            BackingStore::open(tmp.path(), false, BackingMode::Mmap, Some(4096)).unwrap();
        assert_eq!(backing.mode(), BackingMode::Mmap);

        // Write and read back
        backing.write_at(100, &[5, 6, 7, 8]).unwrap();
        let mut buf = [0u8; 4];
        backing.read_at(100, &mut buf).unwrap();
        assert_eq!(buf, [5, 6, 7, 8]);
    }
}
