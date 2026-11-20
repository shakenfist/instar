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
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// One member of a concatenated backing store.
///
/// A member's declared length is what it contributes to the store's
/// address space, and is not the length of its file. A sparse VMDK
/// extent's file stops short of the span its descriptor declares, so
/// `readable_len` can be less than `declared_len` and the difference
/// belongs to this member -- it reads as zeros rather than as the bytes
/// of whatever file follows.
struct ConcatMember {
    file: File,
    /// Offset within the store where this member's declared span begins.
    start: u64,
    /// Bytes this member contributes to the store, whatever its file holds.
    declared_len: u64,
    /// Bytes actually readable from the file, never more than `declared_len`.
    readable_len: u64,
}

/// Where a backing store's bytes come from.
///
/// The single-file case is every device in the VMM except a VMDK
/// descriptor attached together with its extents, so it keeps its own
/// variant and its own code path rather than being a concatenation of
/// one.
enum Storage {
    Single(File),
    Concatenated(Vec<ConcatMember>),
}

/// Backing store for virtio-block devices using buffered file I/O.
pub struct BackingStore {
    storage: Storage,
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
            storage: Storage::Single(file),
            capacity,
            current_size,
            sparse,
        })
    }

    /// Open a read-only backing store spanning several files, read back
    /// to back as one address space.
    ///
    /// `extents` is ordered, and each entry gives a path and the number
    /// of bytes that file contributes. The declared length is deliberately
    /// not taken from the file: a sparse VMDK extent's file is shorter
    /// than the span its descriptor claims, and only the declared length
    /// puts the next member's base in the right place. Bytes inside a
    /// member's span but past the end of its file read as zeros, which is
    /// what the extent itself says is there; continuing into the next file
    /// would hand the caller the following extent's header instead.
    ///
    /// Writing across members is not implemented. A writable request is
    /// refused here rather than accepted and then mishandled per request,
    /// because a write silently landing in the wrong file is worse than a
    /// device that will not open.
    pub fn open_concatenated(extents: &[(PathBuf, u64)], read_only: bool) -> io::Result<Self> {
        if !read_only {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a backing store spanning several files cannot be opened for writing",
            ));
        }

        if extents.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a concatenated backing store needs at least one file",
            ));
        }

        let mut members = Vec::with_capacity(extents.len());
        let mut start = 0u64;
        for (path, declared_len) in extents {
            // The members are the extent files a VMDK descriptor named,
            // and the allowlist says where such a path may point, not
            // what kind of file it may point at. Opening a FIFO blocks
            // until a writer appears, with no timeout, so the operation
            // would hang rather than fail; `O_NONBLOCK` returns
            // instead, and a member that then reads short is padded with
            // zeros like any other. On a regular file the flag does
            // nothing.
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(path)?;
            // A file longer than its declared span contributes only the
            // span: the bytes past it are outside this extent.
            let readable_len = file.metadata()?.len().min(*declared_len);
            members.push(ConcatMember {
                file,
                start,
                declared_len: *declared_len,
                readable_len,
            });
            start = start.checked_add(*declared_len).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "concatenated backing store exceeds the addressable range",
                )
            })?;
        }

        // The whole declared span is addressable, and padding happens per
        // member rather than at the end of the store, so there is no
        // shorter "current size" to track.
        Ok(Self {
            storage: Storage::Concatenated(members),
            capacity: start,
            current_size: start,
            sparse: false,
        })
    }

    /// Open an existing file read-write *without* truncating
    /// it.  Used by `instar resize`, which mutates the file in
    /// place and must preserve every byte not explicitly
    /// rewritten by the planner.
    ///
    /// The capacity exposed to virtio defaults to the file's
    /// current size; pass `capacity` to expose a larger window
    /// when the resize will append.
    pub fn open_rw_existing(path: &Path, capacity: Option<u64>) -> io::Result<Self> {
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        let actual_size = file.metadata()?.len();
        let exposed = capacity.unwrap_or(actual_size).max(actual_size);
        Ok(Self {
            storage: Storage::Single(file),
            capacity: exposed,
            current_size: actual_size,
            sparse: true,
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
        let current_size = self.current_size;

        let file = match &mut self.storage {
            Storage::Single(file) => file,
            Storage::Concatenated(members) => {
                return Self::read_concatenated(members, offset, buf);
            }
        };

        // For sparse files, reading beyond current size returns zeros
        if end > current_size {
            if offset >= current_size {
                // Entire read is beyond file - return zeros
                buf.fill(0);
                return Ok(());
            }
            // Partial read: read what exists, zero the rest
            let existing_bytes = (current_size - offset) as usize;
            file.seek(SeekFrom::Start(offset))?;
            file.read_exact(&mut buf[..existing_bytes])?;
            buf[existing_bytes..].fill(0);
            return Ok(());
        }

        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(buf)
    }

    /// Fill `buf` from a concatenated store, one member at a time.
    ///
    /// Each member owns the half-open span
    /// `[start, start + declared_len)`, and the read is cut at every
    /// boundary it crosses so each file is asked only for its own bytes.
    /// Zero padding is per member, not only at the end of the store:
    /// bytes inside a member's span but past the end of its file are that
    /// member's, and reading them from the next file would return the
    /// following extent's header where zeros belong. A read past the last
    /// member's span returns zeros, matching the single-file path's
    /// behaviour past the end of its file.
    fn read_concatenated(
        members: &mut [ConcatMember],
        offset: u64,
        buf: &mut [u8],
    ) -> io::Result<()> {
        let mut filled = 0usize;

        while filled < buf.len() {
            // `offset + buf.len()` was already checked for overflow.
            let want_at = offset + filled as u64;
            let member = members
                .iter_mut()
                .find(|m| want_at >= m.start && want_at - m.start < m.declared_len);
            let Some(member) = member else {
                // Past the last member's declared span.
                buf[filled..].fill(0);
                return Ok(());
            };

            let within = want_at - member.start;
            // Never read past this member's span, however much the caller
            // asked for: the rest of the buffer belongs to later members.
            let chunk = (member.declared_len - within).min((buf.len() - filled) as u64) as usize;
            let dest = &mut buf[filled..filled + chunk];

            if within >= member.readable_len {
                dest.fill(0);
            } else {
                let from_file = (member.readable_len - within).min(chunk as u64) as usize;
                member.file.seek(SeekFrom::Start(within))?;
                member.file.read_exact(&mut dest[..from_file])?;
                dest[from_file..].fill(0);
            }

            filled += chunk;
        }

        Ok(())
    }

    /// Write data to the backing store at the given offset.
    pub fn write_at(&mut self, offset: u64, buf: &[u8]) -> io::Result<()> {
        let end = Self::checked_end(offset, buf.len())?;

        // A concatenated store is opened read-only, so a write reaching
        // here is a bug in the caller rather than a request to service.
        let file = match &mut self.storage {
            Storage::Single(file) => file,
            Storage::Concatenated(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "a backing store spanning several files is read-only",
                ));
            }
        };

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
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(buf)
    }

    /// Sync data to disk.
    pub fn sync(&self) -> io::Result<()> {
        match &self.storage {
            Storage::Single(file) => file.sync_all(),
            // Nothing here was written, but syncing every member keeps
            // this honest if a write path is ever added.
            Storage::Concatenated(members) => {
                for member in members {
                    member.file.sync_all()?;
                }
                Ok(())
            }
        }
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

    #[test]
    fn test_checked_end_normal() {
        assert_eq!(BackingStore::checked_end(0, 100).unwrap(), 100);
        assert_eq!(BackingStore::checked_end(500, 500).unwrap(), 1000);
    }

    #[test]
    fn test_checked_end_overflow() {
        let result = BackingStore::checked_end(u64::MAX, 1);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn test_write_beyond_capacity_rejected() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&[0u8; 4096]).unwrap();
        tmp.flush().unwrap();

        let mut backing = BackingStore::open(tmp.path(), false, Some(4096), false).unwrap();

        // Write within capacity — should succeed
        backing.write_at(0, &[1, 2, 3, 4]).unwrap();

        // Write that ends exactly at capacity — should succeed
        backing.write_at(4092, &[1, 2, 3, 4]).unwrap();

        // Write that extends 1 byte past capacity — should fail
        let result = backing.write_at(4093, &[1, 2, 3, 4]);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn test_write_beyond_capacity_sparse() {
        let tmp = NamedTempFile::new().unwrap();
        let mut backing = BackingStore::open(tmp.path(), false, Some(4096), true).unwrap();

        // Write within capacity in sparse mode — should succeed
        backing.write_at(4000, &[1, 2, 3, 4]).unwrap();

        // Write beyond capacity in sparse mode — should still be rejected
        let result = backing.write_at(4094, &[1, 2, 3, 4]);
        assert!(result.is_err());
    }

    /// Write `len` bytes of `byte` to a new file in `dir` and return its path.
    fn extent_file(dir: &Path, name: &str, byte: u8, len: usize) -> PathBuf {
        extent_file_with_header(dir, name, &[], byte, len)
    }

    /// As `extent_file`, but the file opens with `header` and is padded to
    /// `len` with `byte`. A real sparse extent opens with its own header,
    /// so this is what a read must *not* see where an earlier extent's
    /// zero padding belongs.
    fn extent_file_with_header(
        dir: &Path,
        name: &str,
        header: &[u8],
        byte: u8,
        len: usize,
    ) -> PathBuf {
        let path = dir.join(name);
        let mut contents = header.to_vec();
        contents.resize(len, byte);
        let mut file = File::create(&path).unwrap();
        file.write_all(&contents).unwrap();
        file.flush().unwrap();
        path
    }

    /// The error from a constructor that must refuse. `BackingStore` is
    /// not `Debug`, which `Result::unwrap_err` requires.
    fn expect_refusal(result: io::Result<BackingStore>, what: &str) -> io::Error {
        match result {
            Ok(_) => panic!("{what}"),
            Err(e) => e,
        }
    }

    #[test]
    fn test_concatenated_read_straddles_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let first = extent_file(dir.path(), "first", 0xAA, 4096);
        let second = extent_file(dir.path(), "second", 0xBB, 4096);

        let mut backing =
            BackingStore::open_concatenated(&[(first, 4096), (second, 4096)], true).unwrap();
        assert_eq!(backing.size(), 8192);

        // Six bytes either side of the boundary come from the two files
        // in order, so neither file is read for the other's bytes.
        let mut buf = [0u8; 12];
        backing.read_at(4090, &mut buf).unwrap();
        assert_eq!(buf[..6], [0xAAu8; 6]);
        assert_eq!(buf[6..], [0xBBu8; 6]);
    }

    #[test]
    fn test_concatenated_read_entirely_past_end() {
        let dir = tempfile::tempdir().unwrap();
        let first = extent_file(dir.path(), "first", 0xAA, 2048);
        let second = extent_file(dir.path(), "second", 0xBB, 2048);

        let mut backing =
            BackingStore::open_concatenated(&[(first, 2048), (second, 2048)], true).unwrap();

        let mut buf = [0xFFu8; 16];
        backing.read_at(4096, &mut buf).unwrap();
        assert_eq!(buf, [0u8; 16]);

        // And a read starting inside the last member but running past the
        // whole store zero-fills only the part that is past it.
        let mut buf = [0xFFu8; 8];
        backing.read_at(4092, &mut buf).unwrap();
        assert_eq!(buf, [0xBB, 0xBB, 0xBB, 0xBB, 0, 0, 0, 0]);
    }

    #[test]
    fn test_concatenated_read_boundary_aligned() {
        let dir = tempfile::tempdir().unwrap();
        let first = extent_file(dir.path(), "first", 0xAA, 512);
        let second = extent_file(dir.path(), "second", 0xBB, 512);
        let third = extent_file(dir.path(), "third", 0xCC, 512);

        let mut backing =
            BackingStore::open_concatenated(&[(first, 512), (second, 512), (third, 512)], true)
                .unwrap();

        // A read that begins exactly on a boundary belongs wholly to the
        // member that starts there, not to the one that ends there.
        let mut buf = [0u8; 512];
        backing.read_at(512, &mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0xBB));

        let mut buf = [0u8; 512];
        backing.read_at(1024, &mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0xCC));

        // A read ending exactly on a boundary stops there.
        let mut buf = [0u8; 512];
        backing.read_at(0, &mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn test_concatenated_second_file_shorter_than_declared() {
        let dir = tempfile::tempdir().unwrap();
        let first = extent_file(dir.path(), "first", 0xAA, 1024);
        // The file holds 256 bytes but declares 1024, as a sparse VMDK
        // extent's file does against the span its descriptor claims.
        let second = extent_file(dir.path(), "second", 0xBB, 256);

        let mut backing =
            BackingStore::open_concatenated(&[(first, 1024), (second, 1024)], true).unwrap();

        // The store spans the declared lengths, not the files' lengths.
        assert_eq!(backing.size(), 2048);

        let mut buf = [0xFFu8; 1024];
        backing.read_at(1024, &mut buf).unwrap();
        assert!(buf[..256].iter().all(|&b| b == 0xBB));
        assert!(buf[256..].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_concatenated_short_extent_pads_rather_than_bleeding() {
        let dir = tempfile::tempdir().unwrap();
        // The first file is short against its declared span, so the bytes
        // between its end and the boundary are its own and must read as
        // zeros. Reading on into the second file would hand back the next
        // extent's leading bytes, which for a sparse VMDK is its header.
        let first = extent_file(dir.path(), "first", 0xAA, 256);
        // The second file opens with a header, as a sparse extent's does.
        let second = extent_file_with_header(dir.path(), "second", &[0xDEu8; 16], 0xBB, 1024);

        let mut backing =
            BackingStore::open_concatenated(&[(first, 1024), (second, 1024)], true).unwrap();

        // Entirely inside the first member's span but past its file.
        let mut buf = [0xFFu8; 64];
        backing.read_at(512, &mut buf).unwrap();
        assert_eq!(buf, [0u8; 64], "a short extent's tail must read as zeros");

        // A read that starts in the first member's padding and crosses into
        // the second gets zeros and then the second member's leading bytes,
        // in that order. The header appearing before the boundary would mean
        // the short file's tail had been filled from the next file.
        let mut buf = [0xFFu8; 32];
        backing.read_at(1008, &mut buf).unwrap();
        assert_eq!(buf[..16], [0u8; 16], "padding before the boundary");
        assert_eq!(
            buf[16..],
            [0xDEu8; 16],
            "the next member's first byte belongs at the boundary"
        );
    }

    // An extent path a descriptor named need not be a regular file, and
    // the backing-file allowlist does not say that it must be. Opening a
    // FIFO without `O_NONBLOCK` blocks until a writer appears, with no
    // timeout, so the operation would hang instead of failing. The open
    // runs on a thread and the answer is waited for, so a regression
    // fails this test rather than stopping the suite (issue #936).
    #[test]
    fn test_concatenated_fifo_member_does_not_block() {
        use std::ffi::CString;
        use std::sync::mpsc;
        use std::time::Duration;

        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("first");
        let as_c = CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: a NUL-terminated path and a mode; its only effect is to
        // create the node, and the return value is checked.
        assert_eq!(
            unsafe { libc::mkfifo(as_c.as_ptr(), 0o600) },
            0,
            "mkfifo: {}",
            std::io::Error::last_os_error()
        );
        let second = extent_file(dir.path(), "second", 0xBB, 1024);

        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let opened = BackingStore::open_concatenated(&[(fifo, 1024), (second, 1024)], true);
            let _ = tx.send(opened.map(|mut store| {
                let mut buf = [0xFFu8; 16];
                let read = store.read_at(0, &mut buf);
                (read.is_ok(), buf)
            }));
        });
        match rx.recv_timeout(Duration::from_secs(20)) {
            Ok(Ok((read_ok, buf))) => {
                assert!(read_ok, "the member reads rather than erroring");
                assert_eq!(
                    buf, [0u8; 16],
                    "a FIFO offers no bytes, so its whole span is this member's padding"
                );
            }
            Ok(Err(e)) => panic!("opening a store with a FIFO member failed: {e}"),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                panic!("opening a FIFO extent blocked")
            }
            Err(other) => panic!("{other}"),
        }
    }

    #[test]
    fn test_concatenated_refuses_writable() {
        let dir = tempfile::tempdir().unwrap();
        let only = extent_file(dir.path(), "only", 0xAA, 512);

        let err = expect_refusal(
            BackingStore::open_concatenated(&[(only, 512)], false),
            "a writable multi-file store must be refused",
        );
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(
            err.to_string().contains("cannot be opened for writing"),
            "unexpected message: {err}"
        );
    }

    #[test]
    fn test_concatenated_write_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let first = extent_file(dir.path(), "first", 0xAA, 512);
        let second = extent_file(dir.path(), "second", 0xBB, 512);

        let mut backing =
            BackingStore::open_concatenated(&[(first, 512), (second, 512)], true).unwrap();

        let result = backing.write_at(0, &[1, 2, 3, 4]);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("read-only"),
            "a write to a concatenated store must say it is read-only"
        );
    }

    #[test]
    fn test_concatenated_rejects_empty() {
        let err = expect_refusal(
            BackingStore::open_concatenated(&[], true),
            "a store with no files must be refused",
        );
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn test_read_with_overflow_offset() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&[0u8; 4096]).unwrap();
        tmp.flush().unwrap();

        let mut backing = BackingStore::open(tmp.path(), true, None, false).unwrap();

        // offset near u64::MAX + any length would overflow
        let result = backing.read_at(u64::MAX, &mut [0u8; 1]);
        assert!(result.is_err());
    }
}
