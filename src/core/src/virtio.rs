//! Virtio block device abstraction for the core guest.
//!
//! Register constants are imported from the shared crate to ensure consistency
//! between guest and host code.

use core::ptr::{read_volatile, write_volatile};

use shared::virtio as shared_virtio;
use shared::MAX_SECTOR_SIZE;

use crate::serial::{send_capacity, send_error, send_init};

// DMA pool base address
const DMA_POOL_BASE: usize = 0x200000;

// Virtio MMIO register offsets (re-exported as usize for pointer arithmetic)
mod reg {
    use super::shared_virtio::reg as shared_reg;

    pub const MAGIC_VALUE: usize = shared_reg::MAGIC_VALUE as usize;
    pub const VERSION: usize = shared_reg::VERSION as usize;
    pub const DEVICE_ID: usize = shared_reg::DEVICE_ID as usize;
    pub const DEVICE_FEATURES: usize = shared_reg::DEVICE_FEATURES as usize;
    pub const DEVICE_FEATURES_SEL: usize = shared_reg::DEVICE_FEATURES_SEL as usize;
    pub const DRIVER_FEATURES: usize = shared_reg::DRIVER_FEATURES as usize;
    pub const DRIVER_FEATURES_SEL: usize = shared_reg::DRIVER_FEATURES_SEL as usize;
    pub const QUEUE_SEL: usize = shared_reg::QUEUE_SEL as usize;
    pub const QUEUE_NUM_MAX: usize = shared_reg::QUEUE_NUM_MAX as usize;
    pub const QUEUE_NUM: usize = shared_reg::QUEUE_NUM as usize;
    pub const QUEUE_READY: usize = shared_reg::QUEUE_READY as usize;
    pub const QUEUE_NOTIFY: usize = shared_reg::QUEUE_NOTIFY as usize;
    pub const INTERRUPT_STATUS: usize = shared_reg::INTERRUPT_STATUS as usize;
    pub const INTERRUPT_ACK: usize = shared_reg::INTERRUPT_ACK as usize;
    pub const STATUS: usize = shared_reg::STATUS as usize;
    pub const QUEUE_DESC_LOW: usize = shared_reg::QUEUE_DESC_LOW as usize;
    pub const QUEUE_DESC_HIGH: usize = shared_reg::QUEUE_DESC_HIGH as usize;
    pub const QUEUE_DRIVER_LOW: usize = shared_reg::QUEUE_DRIVER_LOW as usize;
    pub const QUEUE_DRIVER_HIGH: usize = shared_reg::QUEUE_DRIVER_HIGH as usize;
    pub const QUEUE_DEVICE_LOW: usize = shared_reg::QUEUE_DEVICE_LOW as usize;
    pub const QUEUE_DEVICE_HIGH: usize = shared_reg::QUEUE_DEVICE_HIGH as usize;
    pub const CONFIG: usize = shared_reg::CONFIG as usize;
}

// Device status bits (re-exported as u32 for write_reg compatibility)
mod status {
    use shared::virtio::status as shared_status;

    pub const ACKNOWLEDGE: u32 = shared_status::ACKNOWLEDGE as u32;
    pub const DRIVER: u32 = shared_status::DRIVER as u32;
    pub const DRIVER_OK: u32 = shared_status::DRIVER_OK as u32;
    pub const FEATURES_OK: u32 = shared_status::FEATURES_OK as u32;
}

// Use shared constants directly where types match
use shared_virtio::desc_flags::{NEXT as VIRTQ_DESC_F_NEXT, WRITE as VIRTQ_DESC_F_WRITE};
use shared_virtio::request_status::OK as VIRTIO_BLK_S_OK;
use shared_virtio::request_type::{
    FLUSH as VIRTIO_BLK_T_FLUSH, IN as VIRTIO_BLK_T_IN, OUT as VIRTIO_BLK_T_OUT,
};
use shared_virtio::QUEUE_SIZE_MAX;

// Use shared queue size
const QUEUE_SIZE: u16 = QUEUE_SIZE_MAX;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct VirtqDesc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct VirtioBlkReqHeader {
    type_: u32,
    reserved: u32,
    sector: u64,
}

/// Virtio block device handle
pub struct VirtioBlock {
    mmio_base: usize,
    desc_base: usize,
    avail_base: usize,
    used_base: usize,
    capacity: u64,
    sector_size: usize,
    avail_idx: u16,
    name: &'static str,
}

impl VirtioBlock {
    fn read_reg(&self, offset: usize) -> u32 {
        unsafe { read_volatile((self.mmio_base + offset) as *const u32) }
    }

    fn write_reg(&self, offset: usize, value: u32) {
        unsafe { write_volatile((self.mmio_base + offset) as *mut u32, value) }
    }

    pub fn init(
        mmio_base: usize,
        vq_base: usize,
        sector_size: usize,
        name: &'static str,
    ) -> Option<Self> {
        let dev = Self {
            mmio_base,
            desc_base: vq_base,
            avail_base: vq_base + (QUEUE_SIZE as usize * 16),
            used_base: vq_base + (QUEUE_SIZE as usize * 16) + 6 + (QUEUE_SIZE as usize * 2),
            capacity: 0,
            sector_size,
            avail_idx: 0,
            name,
        };

        send_init("probe", name, mmio_base as u64);
        let magic = dev.read_reg(reg::MAGIC_VALUE);
        if magic != shared_virtio::MAGIC {
            send_error("probe", name, 0, magic);
            return None;
        }

        let version = dev.read_reg(reg::VERSION);
        if version != shared_virtio::VERSION {
            send_error("version", name, 0, version);
            return None;
        }

        let device_id = dev.read_reg(reg::DEVICE_ID);
        if device_id != shared_virtio::DEVICE_ID_BLOCK {
            send_error("device_id", name, 0, device_id);
            return None;
        }

        dev.write_reg(reg::STATUS, 0);
        dev.write_reg(reg::STATUS, status::ACKNOWLEDGE);
        dev.write_reg(reg::STATUS, status::ACKNOWLEDGE | status::DRIVER);

        dev.write_reg(reg::DEVICE_FEATURES_SEL, 0);
        let features_lo = dev.read_reg(reg::DEVICE_FEATURES);
        dev.write_reg(reg::DEVICE_FEATURES_SEL, 1);
        let features_hi = dev.read_reg(reg::DEVICE_FEATURES);
        let features = (features_lo as u64) | ((features_hi as u64) << 32);
        send_init("features", name, features);

        dev.write_reg(reg::DRIVER_FEATURES_SEL, 0);
        dev.write_reg(reg::DRIVER_FEATURES, 0);
        dev.write_reg(reg::DRIVER_FEATURES_SEL, 1);
        dev.write_reg(reg::DRIVER_FEATURES, 1);

        dev.write_reg(
            reg::STATUS,
            status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK,
        );

        let dev_status = dev.read_reg(reg::STATUS);
        if dev_status & status::FEATURES_OK == 0 {
            send_error("features_ok", name, 0, dev_status);
            return None;
        }

        dev.write_reg(reg::QUEUE_SEL, 0);
        let max_size = dev.read_reg(reg::QUEUE_NUM_MAX) as u16;
        let queue_size = if max_size < QUEUE_SIZE {
            max_size
        } else {
            QUEUE_SIZE
        };
        dev.write_reg(reg::QUEUE_NUM, queue_size as u32);
        send_init("queue", name, queue_size as u64);

        let desc_addr = dev.desc_base as u64;
        let avail_addr = dev.avail_base as u64;
        let used_addr = dev.used_base as u64;

        dev.write_reg(reg::QUEUE_DESC_LOW, desc_addr as u32);
        dev.write_reg(reg::QUEUE_DESC_HIGH, (desc_addr >> 32) as u32);
        dev.write_reg(reg::QUEUE_DRIVER_LOW, avail_addr as u32);
        dev.write_reg(reg::QUEUE_DRIVER_HIGH, (avail_addr >> 32) as u32);
        dev.write_reg(reg::QUEUE_DEVICE_LOW, used_addr as u32);
        dev.write_reg(reg::QUEUE_DEVICE_HIGH, (used_addr >> 32) as u32);

        dev.write_reg(reg::QUEUE_READY, 1);
        dev.write_reg(
            reg::STATUS,
            status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK | status::DRIVER_OK,
        );

        let cap_lo = dev.read_reg(reg::CONFIG);
        let cap_hi = dev.read_reg(reg::CONFIG + 4);
        let capacity = (cap_lo as u64) | ((cap_hi as u64) << 32);

        send_capacity(name, capacity, capacity * sector_size as u64);
        send_init("sector_size", name, sector_size as u64);

        Some(Self { capacity, ..dev })
    }

    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    pub fn sector_size(&self) -> usize {
        self.sector_size
    }

    pub fn read_sector(&mut self, sector: u64, buffer: &mut [u8]) -> bool {
        if buffer.len() < self.sector_size {
            return false;
        }
        self.do_request(VIRTIO_BLK_T_IN, sector, buffer)
    }

    pub fn write_sector(&mut self, sector: u64, buffer: &[u8]) -> bool {
        if buffer.len() < self.sector_size {
            return false;
        }
        let mut buf = [0u8; MAX_SECTOR_SIZE];
        buf[..self.sector_size].copy_from_slice(&buffer[..self.sector_size]);
        self.do_request(VIRTIO_BLK_T_OUT, sector, &mut buf[..self.sector_size])
    }

    /// Request a host-side `fdatasync` of the backing file.
    ///
    /// Used by mutating snapshot modes (and, eventually, commit)
    /// between the data-write pass and the header-pointer flip
    /// to enforce qemu's "old table still valid until header
    /// updated" durability contract.
    ///
    /// Issues a `VIRTIO_BLK_T_FLUSH` request on the same
    /// 3-descriptor chain `do_request` uses; the host VMM block
    /// emulator (`src/vmm/src/virtio/block.rs`) reads the data
    /// descriptor for layout reasons but ignores its contents
    /// for FLUSH and calls `File::sync_all()` on the backing.
    pub fn flush(&mut self) -> bool {
        let mut buf = [0u8; MAX_SECTOR_SIZE];
        self.do_request(VIRTIO_BLK_T_FLUSH, 0, &mut buf[..self.sector_size])
    }

    fn do_request(&mut self, req_type: u32, sector: u64, buffer: &mut [u8]) -> bool {
        let header_addr = DMA_POOL_BASE as u64;
        let data_addr = header_addr + 16;
        let status_addr = data_addr + self.sector_size as u64;

        let header = VirtioBlkReqHeader {
            type_: req_type,
            reserved: 0,
            sector,
        };
        unsafe {
            write_volatile(header_addr as *mut VirtioBlkReqHeader, header);
        }

        if req_type == VIRTIO_BLK_T_OUT {
            unsafe {
                let data_ptr = data_addr as *mut u8;
                for (i, &byte) in buffer[..self.sector_size].iter().enumerate() {
                    write_volatile(data_ptr.add(i), byte);
                }
            }
        }

        unsafe {
            write_volatile(status_addr as *mut u8, 0xFF);
        }

        let desc_idx = (self.avail_idx % (QUEUE_SIZE / 3)) * 3;
        self.write_desc(desc_idx, header_addr, 16, VIRTQ_DESC_F_NEXT, desc_idx + 1);

        let data_flags = if req_type == VIRTIO_BLK_T_IN {
            VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE
        } else {
            VIRTQ_DESC_F_NEXT
        };
        self.write_desc(
            desc_idx + 1,
            data_addr,
            self.sector_size as u32,
            data_flags,
            desc_idx + 2,
        );
        self.write_desc(desc_idx + 2, status_addr, 1, VIRTQ_DESC_F_WRITE, 0);

        let avail_idx = self.avail_idx;
        let ring_idx = avail_idx % QUEUE_SIZE;

        unsafe {
            let avail_ring = (self.avail_base + 4 + (ring_idx as usize * 2)) as *mut u16;
            write_volatile(avail_ring, desc_idx);
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            let avail_idx_ptr = (self.avail_base + 2) as *mut u16;
            write_volatile(avail_idx_ptr, avail_idx.wrapping_add(1));
        }

        self.avail_idx = avail_idx.wrapping_add(1);
        self.write_reg(reg::QUEUE_NOTIFY, 0);

        // Wait for device to process the request with timeout.
        // In bare-metal no_std, we use iteration count as a timeout mechanism.
        // 100M iterations is generous - typical I/O completes in <1M iterations.
        const MAX_WAIT_ITERATIONS: u64 = 100_000_000;

        let expected_used_idx = avail_idx.wrapping_add(1);
        let mut timed_out = true;
        for _ in 0..MAX_WAIT_ITERATIONS {
            unsafe {
                let used_idx = read_volatile((self.used_base + 2) as *const u16);
                if used_idx == expected_used_idx {
                    timed_out = false;
                    break;
                }
            }
            core::hint::spin_loop();
        }

        if timed_out {
            send_error("timeout", self.name, sector, 0xDEAD);
            return false;
        }

        let int_status = self.read_reg(reg::INTERRUPT_STATUS);
        if int_status != 0 {
            self.write_reg(reg::INTERRUPT_ACK, int_status);
        }

        let status = unsafe { read_volatile(status_addr as *const u8) };

        if req_type == VIRTIO_BLK_T_IN && status == VIRTIO_BLK_S_OK {
            unsafe {
                let data_ptr = data_addr as *const u8;
                for (i, byte) in buffer[..self.sector_size].iter_mut().enumerate() {
                    *byte = read_volatile(data_ptr.add(i));
                }
            }
        }

        status == VIRTIO_BLK_S_OK
    }

    fn write_desc(&self, idx: u16, addr: u64, len: u32, flags: u16, next: u16) {
        let desc = VirtqDesc {
            addr,
            len,
            flags,
            next,
        };
        unsafe {
            let desc_ptr = (self.desc_base + (idx as usize * 16)) as *mut VirtqDesc;
            write_volatile(desc_ptr, desc);
        }
    }
}
