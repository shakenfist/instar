//! Backing store implementation for virtio-block devices.
//!
//! Uses regular buffered file I/O with the kernel page cache, which provides
//! optimal performance for sequential workloads like file copying through
//! read-ahead and write coalescing.
//!
//! For output devices, supports "sparse" mode where the file is not
//! pre-allocated and grows on demand as sectors are written.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

/// Backing store for virtio-block devices using buffered file I/O.
pub struct BackingStore {
    file: File,
    /// Capacity exposed to the device (may be larger than actual file size in sparse mode)
    capacity: u64,
    /// Current actual file size (tracked for sparse mode)
    current_size: u64,
    /// Whether the file grows on demand (sparse mode)
    sparse: bool,
}

impl BackingStore {
    /// Open a backing store.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the backing file
    /// * `read_only` - Whether the file is read-only
    /// * `capacity` - For write mode: the capacity to expose (may be larger than
    ///   actual file). For read mode: ignored, uses actual file size.
    /// * `sparse` - If true, don't pre-allocate the file; let it grow on demand.
    ///   Only applicable for writable files.
    pub fn open(
        path: &Path,
        read_only: bool,
        capacity: Option<u64>,
        sparse: bool,
    ) -> io::Result<Self> {
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

        let (capacity, current_size) = if let Some(cap) = capacity {
            if !read_only && !sparse {
                // Pre-allocate to full capacity
                file.set_len(cap)?;
                (cap, cap)
            } else {
                // Sparse mode or read-only: file grows on demand
                let actual_size = file.metadata()?.len();
                (cap, actual_size)
            }
        } else {
            let actual_size = file.metadata()?.len();
            (actual_size, actual_size)
        };

        Ok(Self {
            file,
            capacity,
            current_size,
            sparse,
        })
    }

    /// Compute `offset + buf.len()` with overflow checking.
    fn checked_end(offset: u64, len: usize) -> io::Result<u64> {
        offset
            .checked_add(len as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "offset + length overflow"))
    }

    /// Read data from the backing store at the given offset.
    pub fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let end = Self::checked_end(offset, buf.len())?;

        // For sparse files, reading beyond current size returns zeros
        if end > self.current_size {
            if offset >= self.current_size {
                // Entire read is beyond file - return zeros
                buf.fill(0);
                return Ok(());
            }
            // Partial read: read what exists, zero the rest
            let existing_bytes = (self.current_size - offset) as usize;
            self.file.seek(SeekFrom::Start(offset))?;
            self.file.read_exact(&mut buf[..existing_bytes])?;
            buf[existing_bytes..].fill(0);
            return Ok(());
        }

        self.file.seek(SeekFrom::Start(offset))?;
        self.file.read_exact(buf)
    }

    /// Write data to the backing store at the given offset.
    pub fn write_at(&mut self, offset: u64, buf: &[u8]) -> io::Result<()> {
        let end = Self::checked_end(offset, buf.len())?;

        // Reject writes beyond the device capacity
        if end > self.capacity {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "write at offset {} + {} bytes exceeds capacity {}",
                    offset,
                    buf.len(),
                    self.capacity
                ),
            ));
        }

        // In sparse mode, track the growing file size
        if self.sparse && end > self.current_size {
            self.current_size = end;
        }

        // seek + write_all automatically extends the file on Linux
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(buf)
    }

    /// Sync data to disk.
    pub fn sync(&self) -> io::Result<()> {
        self.file.sync_all()
    }

    /// Get the capacity of the backing store.
    #[allow(dead_code)]
    pub fn size(&self) -> u64 {
        self.capacity
    }

    /// Check if this backing store is in sparse mode.
    #[allow(dead_code)]
    pub fn is_sparse(&self) -> bool {
        self.sparse
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

        let mut backing = BackingStore::open(tmp.path(), false, Some(4096), false).unwrap();
        assert_eq!(backing.size(), 4096);
        assert!(!backing.is_sparse());

        // Write and read back
        backing.write_at(0, &[1, 2, 3, 4]).unwrap();
        let mut buf = [0u8; 4];
        backing.read_at(0, &mut buf).unwrap();
        assert_eq!(buf, [1, 2, 3, 4]);
    }

    #[test]
    fn test_sparse_backing() {
        let tmp = NamedTempFile::new().unwrap();

        // Open with sparse mode - capacity 4096 but no pre-allocation
        let mut backing = BackingStore::open(tmp.path(), false, Some(4096), true).unwrap();
        assert_eq!(backing.size(), 4096); // Capacity is 4096
        assert!(backing.is_sparse());

        // Write at offset 100 - file should grow to include this
        backing.write_at(100, &[1, 2, 3, 4]).unwrap();

        // Read back what we wrote
        let mut buf = [0u8; 4];
        backing.read_at(100, &mut buf).unwrap();
        assert_eq!(buf, [1, 2, 3, 4]);

        // Read beyond what we've written (but within capacity) - should return zeros
        let mut buf2 = [0xFFu8; 4];
        backing.read_at(1000, &mut buf2).unwrap();
        assert_eq!(buf2, [0, 0, 0, 0]);
    }
}
