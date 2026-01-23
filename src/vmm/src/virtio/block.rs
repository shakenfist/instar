//! Virtio block device implementation.
//!
//! Implements a virtio-block device backed by buffered file I/O with
//! support for sparse output files that grow on demand.

use vm_memory::{ByteValued, Bytes, GuestAddress, GuestMemoryMmap};

use super::mmio::{
    features, reg, MmioState, DEVICE_ID_BLOCK, MAGIC, QUEUE_SIZE_MAX, VENDOR_ID, VERSION,
};
use crate::backing::BackingStore;

/// Statistics for a single queue processing operation.
#[derive(Debug, Default, Clone, Copy)]
pub struct IoStats {
    /// Bytes read from the backing file
    pub bytes_read: u64,
    /// Bytes written to the backing file
    pub bytes_written: u64,
    /// Sectors read
    pub sectors_read: u64,
    /// Sectors written
    pub sectors_written: u64,
}

/// Block request types
mod request_type {
    pub const IN: u32 = 0; // Read
    pub const OUT: u32 = 1; // Write
    pub const FLUSH: u32 = 4;
}

/// Block request status
mod request_status {
    pub const OK: u8 = 0;
    pub const IOERR: u8 = 1;
    pub const UNSUPP: u8 = 2;
}

/// Virtio block request header
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct VirtioBlkReqHeader {
    type_: u32,
    reserved: u32,
    sector: u64,
}

/// Virtqueue descriptor
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct VirtqDesc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

impl VirtqDesc {
    const F_NEXT: u16 = 1;
    const F_WRITE: u16 = 2;
}

/// Virtqueue available ring header
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct VirtqAvail {
    flags: u16,
    idx: u16,
    // ring: [u16; queue_size] follows
}

/// Virtqueue used element
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct VirtqUsedElem {
    id: u32,
    len: u32,
}

/// Virtqueue used ring header
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct VirtqUsed {
    flags: u16,
    idx: u16,
    // ring: [VirtqUsedElem; queue_size] follows
}

// SAFETY: All these structs are #[repr(C)] with only POD types (u8, u16, u32, u64).
// They have no padding that could cause undefined behavior when read as bytes.
unsafe impl ByteValued for VirtioBlkReqHeader {}
unsafe impl ByteValued for VirtqDesc {}
unsafe impl ByteValued for VirtqAvail {}
unsafe impl ByteValued for VirtqUsedElem {}
unsafe impl ByteValued for VirtqUsed {}

/// Virtio block device
pub struct VirtioBlockDevice {
    backing: BackingStore,
    capacity: u64,    // in sectors (based on sector_size)
    sector_size: u64, // configurable sector size in bytes
    read_only: bool,
    mmio_base: u64,
    _vq_base: u64, // Reserved for future use
    state: MmioState,
}

impl VirtioBlockDevice {
    /// Create a new virtio block device with configurable sector size.
    ///
    /// # Arguments
    ///
    /// * `backing` - The backing store
    /// * `size_bytes` - Total size of the device in bytes
    /// * `sector_size` - Sector size in bytes (e.g., 512, 4096)
    /// * `read_only` - Whether the device is read-only
    /// * `mmio_base` - MMIO base address
    /// * `vq_base` - Virtqueue base address
    pub fn new(
        backing: BackingStore,
        size_bytes: u64,
        sector_size: u64,
        read_only: bool,
        mmio_base: u64,
        vq_base: u64,
    ) -> Self {
        Self {
            backing,
            capacity: size_bytes / sector_size,
            sector_size,
            read_only,
            mmio_base,
            _vq_base: vq_base,
            state: MmioState::default(),
        }
    }

    /// Get the sector size
    pub fn sector_size(&self) -> u64 {
        self.sector_size
    }

    /// Get the MMIO base address
    #[allow(dead_code)]
    pub fn mmio_base(&self) -> u64 {
        self.mmio_base
    }

    /// Get the device features
    fn device_features(&self) -> u64 {
        let mut features = features::VIRTIO_F_VERSION_1;
        if self.read_only {
            features |= features::VIRTIO_BLK_F_RO;
        }
        features
    }

    /// Handle MMIO read
    pub fn mmio_read(&self, offset: u32) -> u32 {
        match offset {
            reg::MAGIC_VALUE => MAGIC,
            reg::VERSION => VERSION,
            reg::DEVICE_ID => DEVICE_ID_BLOCK,
            reg::VENDOR_ID => VENDOR_ID,
            reg::DEVICE_FEATURES => {
                let features = self.device_features();
                if self.state.device_features_sel == 0 {
                    features as u32
                } else {
                    (features >> 32) as u32
                }
            }
            reg::QUEUE_NUM_MAX => QUEUE_SIZE_MAX as u32,
            reg::QUEUE_READY => {
                if self.state.current_queue().ready {
                    1
                } else {
                    0
                }
            }
            reg::INTERRUPT_STATUS => self.state.interrupt_status,
            reg::STATUS => self.state.status as u32,
            reg::CONFIG_GENERATION => 0,
            // Block device config: capacity (8 bytes at offset 0x100)
            reg::CONFIG => self.capacity as u32,
            0x104 => (self.capacity >> 32) as u32,
            _ => {
                println!(
                    "Unhandled MMIO read at offset 0x{:x} (base 0x{:x})",
                    offset, self.mmio_base
                );
                0
            }
        }
    }

    /// Handle MMIO write
    pub fn mmio_write(&mut self, offset: u32, value: u32) {
        match offset {
            reg::DEVICE_FEATURES_SEL => {
                self.state.device_features_sel = value;
            }
            reg::DRIVER_FEATURES => {
                if self.state.driver_features_sel == 0 {
                    self.state.driver_features =
                        (self.state.driver_features & 0xFFFF_FFFF_0000_0000) | (value as u64);
                } else {
                    self.state.driver_features = (self.state.driver_features
                        & 0x0000_0000_FFFF_FFFF)
                        | ((value as u64) << 32);
                }
            }
            reg::DRIVER_FEATURES_SEL => {
                self.state.driver_features_sel = value;
            }
            reg::QUEUE_SEL => {
                self.state.queue_sel = value;
            }
            reg::QUEUE_NUM => {
                self.state.current_queue_mut().num = value as u16;
            }
            reg::QUEUE_READY => {
                self.state.current_queue_mut().ready = value != 0;
            }
            reg::QUEUE_NOTIFY => {
                self.state.queue_notify_pending = true;
            }
            reg::INTERRUPT_ACK => {
                self.state.interrupt_status &= !value;
            }
            reg::STATUS => {
                let new_status = value as u8;
                if new_status == 0 {
                    // Device reset
                    self.state.reset();
                } else {
                    self.state.status = new_status;
                }
            }
            reg::QUEUE_DESC_LOW => {
                let queue = self.state.current_queue_mut();
                queue.desc_addr = (queue.desc_addr & 0xFFFF_FFFF_0000_0000) | (value as u64);
            }
            reg::QUEUE_DESC_HIGH => {
                let queue = self.state.current_queue_mut();
                queue.desc_addr =
                    (queue.desc_addr & 0x0000_0000_FFFF_FFFF) | ((value as u64) << 32);
            }
            reg::QUEUE_DRIVER_LOW => {
                let queue = self.state.current_queue_mut();
                queue.driver_addr = (queue.driver_addr & 0xFFFF_FFFF_0000_0000) | (value as u64);
            }
            reg::QUEUE_DRIVER_HIGH => {
                let queue = self.state.current_queue_mut();
                queue.driver_addr =
                    (queue.driver_addr & 0x0000_0000_FFFF_FFFF) | ((value as u64) << 32);
            }
            reg::QUEUE_DEVICE_LOW => {
                let queue = self.state.current_queue_mut();
                queue.device_addr = (queue.device_addr & 0xFFFF_FFFF_0000_0000) | (value as u64);
            }
            reg::QUEUE_DEVICE_HIGH => {
                let queue = self.state.current_queue_mut();
                queue.device_addr =
                    (queue.device_addr & 0x0000_0000_FFFF_FFFF) | ((value as u64) << 32);
            }
            _ => {
                println!(
                    "Unhandled MMIO write at offset 0x{:x} = 0x{:x} (base 0x{:x})",
                    offset, value, self.mmio_base
                );
            }
        }
    }

    /// Check if we should process the queue
    pub fn should_process_queue(&self) -> bool {
        self.state.queue_notify_pending
    }

    /// Mark queue as needing processing (called when ioeventfd signals)
    pub fn set_queue_notify(&mut self) {
        self.state.queue_notify_pending = true;
    }

    /// Process pending virtqueue requests.
    ///
    /// Returns I/O statistics for the operations performed.
    pub fn process_queue(
        &mut self,
        guest_mem: &GuestMemoryMmap,
    ) -> Result<IoStats, Box<dyn std::error::Error>> {
        self.state.queue_notify_pending = false;

        let mut stats = IoStats::default();

        let queue = &self.state.queues[0];
        if !queue.ready || queue.num == 0 {
            return Ok(stats);
        }

        let desc_addr = queue.desc_addr;
        let driver_addr = queue.driver_addr;
        let device_addr = queue.device_addr;
        let queue_size = queue.num;

        // Read available ring header
        let avail: VirtqAvail = guest_mem.read_obj(GuestAddress(driver_addr))?;
        let mut last_avail_idx = self.state.queues[0].last_avail_idx;

        // Process available descriptors
        while last_avail_idx != avail.idx {
            let ring_idx = last_avail_idx % queue_size;
            let ring_entry_addr = driver_addr + 4 + (ring_idx as u64 * 2);
            let desc_idx: u16 = guest_mem.read_obj(GuestAddress(ring_entry_addr))?;

            // Process the descriptor chain
            let (bytes_written, req_stats) =
                self.process_request(guest_mem, desc_addr, desc_idx, queue_size)?;

            // Accumulate stats
            stats.bytes_read += req_stats.bytes_read;
            stats.bytes_written += req_stats.bytes_written;
            stats.sectors_read += req_stats.sectors_read;
            stats.sectors_written += req_stats.sectors_written;

            // Write to used ring
            let used: VirtqUsed = guest_mem.read_obj(GuestAddress(device_addr))?;
            let used_ring_idx = used.idx % queue_size;
            let used_elem_addr = device_addr + 4 + (used_ring_idx as u64 * 8);
            let used_elem = VirtqUsedElem {
                id: desc_idx as u32,
                len: bytes_written,
            };
            guest_mem.write_obj(used_elem, GuestAddress(used_elem_addr))?;

            // Update used index
            let new_used_idx = used.idx.wrapping_add(1);
            guest_mem.write_obj(new_used_idx, GuestAddress(device_addr + 2))?;

            last_avail_idx = last_avail_idx.wrapping_add(1);
        }

        self.state.queues[0].last_avail_idx = last_avail_idx;

        // Signal interrupt
        self.state.interrupt_status |= 1;

        Ok(stats)
    }

    /// Process a single block request.
    ///
    /// Returns (bytes_written_to_used_ring, io_stats).
    fn process_request(
        &mut self,
        guest_mem: &GuestMemoryMmap,
        desc_table_addr: u64,
        first_desc_idx: u16,
        _queue_size: u16,
    ) -> Result<(u32, IoStats), Box<dyn std::error::Error>> {
        let mut desc_idx = first_desc_idx;
        let mut total_written = 0u32;
        let mut stats = IoStats::default();

        // Read header descriptor
        let header_desc: VirtqDesc =
            guest_mem.read_obj(GuestAddress(desc_table_addr + (desc_idx as u64 * 16)))?;
        let header: VirtioBlkReqHeader = guest_mem.read_obj(GuestAddress(header_desc.addr))?;

        // Move to data descriptor
        if header_desc.flags & VirtqDesc::F_NEXT == 0 {
            return Err("Missing data descriptor".into());
        }
        desc_idx = header_desc.next;

        // Read data descriptor
        let data_desc: VirtqDesc =
            guest_mem.read_obj(GuestAddress(desc_table_addr + (desc_idx as u64 * 16)))?;

        // Process based on request type
        let status = match header.type_ {
            request_type::IN => {
                // Read from file to guest
                if data_desc.flags & VirtqDesc::F_WRITE == 0 {
                    request_status::IOERR
                } else {
                    let result =
                        self.do_read(guest_mem, header.sector, data_desc.addr, data_desc.len)?;
                    if result == request_status::OK {
                        stats.bytes_read = data_desc.len as u64;
                        stats.sectors_read = (data_desc.len as u64).div_ceil(self.sector_size);
                    }
                    result
                }
            }
            request_type::OUT => {
                // Write from guest to file
                // Error if device is read-only OR if descriptor is marked as device-write
                // (for OUT requests, the descriptor should be device-read)
                if self.read_only || (data_desc.flags & VirtqDesc::F_WRITE != 0) {
                    request_status::IOERR
                } else {
                    let result =
                        self.do_write(guest_mem, header.sector, data_desc.addr, data_desc.len)?;
                    if result == request_status::OK {
                        stats.bytes_written = data_desc.len as u64;
                        stats.sectors_written = (data_desc.len as u64).div_ceil(self.sector_size);
                    }
                    result
                }
            }
            request_type::FLUSH => {
                self.backing.sync()?;
                request_status::OK
            }
            _ => request_status::UNSUPP,
        };

        total_written += data_desc.len;

        // Move to status descriptor
        if data_desc.flags & VirtqDesc::F_NEXT == 0 {
            return Err("Missing status descriptor".into());
        }
        desc_idx = data_desc.next;

        // Write status
        let status_desc: VirtqDesc =
            guest_mem.read_obj(GuestAddress(desc_table_addr + (desc_idx as u64 * 16)))?;
        guest_mem.write_obj(status, GuestAddress(status_desc.addr))?;
        total_written += 1;

        Ok((total_written, stats))
    }

    /// Read from backing store to guest memory
    fn do_read(
        &mut self,
        guest_mem: &GuestMemoryMmap,
        sector: u64,
        addr: u64,
        len: u32,
    ) -> Result<u8, Box<dyn std::error::Error>> {
        let offset = sector * self.sector_size;

        let mut buf = vec![0u8; len as usize];
        self.backing.read_at(offset, &mut buf)?;

        guest_mem.write_slice(&buf, GuestAddress(addr))?;
        Ok(request_status::OK)
    }

    /// Write from guest memory to backing store
    fn do_write(
        &mut self,
        guest_mem: &GuestMemoryMmap,
        sector: u64,
        addr: u64,
        len: u32,
    ) -> Result<u8, Box<dyn std::error::Error>> {
        let offset = sector * self.sector_size;

        let mut buf = vec![0u8; len as usize];
        guest_mem.read_slice(&mut buf, GuestAddress(addr))?;

        self.backing.write_at(offset, &buf)?;
        Ok(request_status::OK)
    }
}
