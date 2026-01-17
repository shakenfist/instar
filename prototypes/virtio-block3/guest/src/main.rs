//! Bare-metal guest that copies data between virtio-block devices.
//!
//! This guest reads configuration from the VMM over serial at startup to
//! determine the sector sizes for input and output devices. It then
//! initializes two virtio-block devices and copies all sectors from input
//! to output. Progress and status are reported via structured protobuf
//! messages over the serial port.

#![no_std]
#![no_main]

mod serial;

use core::arch::asm;
use core::panic::PanicInfo;
use core::ptr::{read_volatile, write_volatile};

use serial::{
    debug_print, read_config, send_capacity, send_complete, send_error, send_init, send_progress,
    DeviceConfig,
};

// Memory layout (must match VMM)
// MMIO addresses are outside guest memory (256MB) so KVM generates MMIO exits
const INPUT_MMIO_BASE: usize = 0x10000000;
const OUTPUT_MMIO_BASE: usize = 0x10001000;
// Virtqueue and DMA regions are inside guest memory (8MB)
const INPUT_VQ_BASE: usize = 0x100000;
const OUTPUT_VQ_BASE: usize = 0x110000;
const DMA_POOL_BASE: usize = 0x200000;

// Maximum sector size we support (for DMA buffer allocation)
const MAX_SECTOR_SIZE: usize = 65536; // 64KB

// Virtio MMIO register offsets
mod reg {
    pub const MAGIC_VALUE: usize = 0x000;
    pub const VERSION: usize = 0x004;
    pub const DEVICE_ID: usize = 0x008;
    pub const DEVICE_FEATURES: usize = 0x010;
    pub const DEVICE_FEATURES_SEL: usize = 0x014;
    pub const DRIVER_FEATURES: usize = 0x020;
    pub const DRIVER_FEATURES_SEL: usize = 0x024;
    pub const QUEUE_SEL: usize = 0x030;
    pub const QUEUE_NUM_MAX: usize = 0x034;
    pub const QUEUE_NUM: usize = 0x038;
    pub const QUEUE_READY: usize = 0x044;
    pub const QUEUE_NOTIFY: usize = 0x050;
    pub const INTERRUPT_STATUS: usize = 0x060;
    pub const INTERRUPT_ACK: usize = 0x064;
    pub const STATUS: usize = 0x070;
    pub const QUEUE_DESC_LOW: usize = 0x080;
    pub const QUEUE_DESC_HIGH: usize = 0x084;
    pub const QUEUE_DRIVER_LOW: usize = 0x090;
    pub const QUEUE_DRIVER_HIGH: usize = 0x094;
    pub const QUEUE_DEVICE_LOW: usize = 0x0A0;
    pub const QUEUE_DEVICE_HIGH: usize = 0x0A4;
    pub const CONFIG: usize = 0x100;
}

// Virtio status bits
mod status {
    pub const ACKNOWLEDGE: u32 = 1;
    pub const DRIVER: u32 = 2;
    pub const DRIVER_OK: u32 = 4;
    pub const FEATURES_OK: u32 = 8;
}

// Block request types
const VIRTIO_BLK_T_IN: u32 = 0; // Read
const VIRTIO_BLK_T_OUT: u32 = 1; // Write

// Block status
const VIRTIO_BLK_S_OK: u8 = 0;

// Descriptor flags
const VIRTQ_DESC_F_NEXT: u16 = 1;
const VIRTQ_DESC_F_WRITE: u16 = 2;

// Queue size
const QUEUE_SIZE: u16 = 256;

/// Virtqueue descriptor
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct VirtqDesc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

/// Block request header
#[repr(C)]
#[derive(Clone, Copy)]
struct VirtioBlkReqHeader {
    type_: u32,
    reserved: u32,
    sector: u64,
}

/// Virtio block device handle
struct VirtioBlock {
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
    /// Read MMIO register
    fn read_reg(&self, offset: usize) -> u32 {
        unsafe { read_volatile((self.mmio_base + offset) as *const u32) }
    }

    /// Write MMIO register
    fn write_reg(&self, offset: usize, value: u32) {
        unsafe { write_volatile((self.mmio_base + offset) as *mut u32, value) }
    }

    /// Initialize a virtio block device with specified sector size
    fn init(
        mmio_base: usize,
        vq_base: usize,
        sector_size: usize,
        name: &'static str,
    ) -> Option<Self> {
        let dev = Self {
            mmio_base,
            desc_base: vq_base,
            avail_base: vq_base + (QUEUE_SIZE as usize * 16), // After descriptors
            used_base: vq_base + (QUEUE_SIZE as usize * 16) + 6 + (QUEUE_SIZE as usize * 2),
            capacity: 0,
            sector_size,
            avail_idx: 0,
            name,
        };

        // Check magic
        send_init("probe", name, mmio_base as u64);
        let magic = dev.read_reg(reg::MAGIC_VALUE);
        if magic != 0x74726976 {
            send_error("probe", name, 0, magic);
            return None;
        }

        // Check version
        let version = dev.read_reg(reg::VERSION);
        if version != 2 {
            send_error("version", name, 0, version);
            return None;
        }

        // Check device ID (2 = block)
        let device_id = dev.read_reg(reg::DEVICE_ID);
        if device_id != 2 {
            send_error("device_id", name, 0, device_id);
            return None;
        }

        // Reset device
        dev.write_reg(reg::STATUS, 0);

        // Acknowledge
        dev.write_reg(reg::STATUS, status::ACKNOWLEDGE);

        // Driver
        dev.write_reg(reg::STATUS, status::ACKNOWLEDGE | status::DRIVER);

        // Read features
        dev.write_reg(reg::DEVICE_FEATURES_SEL, 0);
        let features_lo = dev.read_reg(reg::DEVICE_FEATURES);
        dev.write_reg(reg::DEVICE_FEATURES_SEL, 1);
        let features_hi = dev.read_reg(reg::DEVICE_FEATURES);
        let features = (features_lo as u64) | ((features_hi as u64) << 32);
        send_init("features", name, features);

        // Accept VIRTIO_F_VERSION_1 (bit 32)
        dev.write_reg(reg::DRIVER_FEATURES_SEL, 0);
        dev.write_reg(reg::DRIVER_FEATURES, 0);
        dev.write_reg(reg::DRIVER_FEATURES_SEL, 1);
        dev.write_reg(reg::DRIVER_FEATURES, 1); // VERSION_1

        // Features OK
        dev.write_reg(
            reg::STATUS,
            status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK,
        );

        // Check features accepted
        let dev_status = dev.read_reg(reg::STATUS);
        if dev_status & status::FEATURES_OK == 0 {
            send_error("features_ok", name, 0, dev_status);
            return None;
        }

        // Configure queue
        dev.write_reg(reg::QUEUE_SEL, 0);

        let max_size = dev.read_reg(reg::QUEUE_NUM_MAX) as u16;
        let queue_size = if max_size < QUEUE_SIZE {
            max_size
        } else {
            QUEUE_SIZE
        };

        dev.write_reg(reg::QUEUE_NUM, queue_size as u32);
        send_init("queue", name, queue_size as u64);

        // Set queue addresses
        let desc_addr = dev.desc_base as u64;
        let avail_addr = dev.avail_base as u64;
        let used_addr = dev.used_base as u64;

        dev.write_reg(reg::QUEUE_DESC_LOW, desc_addr as u32);
        dev.write_reg(reg::QUEUE_DESC_HIGH, (desc_addr >> 32) as u32);
        dev.write_reg(reg::QUEUE_DRIVER_LOW, avail_addr as u32);
        dev.write_reg(reg::QUEUE_DRIVER_HIGH, (avail_addr >> 32) as u32);
        dev.write_reg(reg::QUEUE_DEVICE_LOW, used_addr as u32);
        dev.write_reg(reg::QUEUE_DEVICE_HIGH, (used_addr >> 32) as u32);

        // Queue ready
        dev.write_reg(reg::QUEUE_READY, 1);

        // Driver OK
        dev.write_reg(
            reg::STATUS,
            status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK | status::DRIVER_OK,
        );

        // Read capacity from config (in device's sector units)
        let cap_lo = dev.read_reg(reg::CONFIG);
        let cap_hi = dev.read_reg(reg::CONFIG + 4);
        let capacity = (cap_lo as u64) | ((cap_hi as u64) << 32);

        send_capacity(name, capacity, capacity * sector_size as u64);
        send_init("sector_size", name, sector_size as u64);

        Some(Self { capacity, ..dev })
    }

    /// Read a sector into a dynamically-sized buffer
    fn read_sector(&mut self, sector: u64, buffer: &mut [u8]) -> bool {
        if buffer.len() < self.sector_size {
            return false;
        }
        self.do_request(VIRTIO_BLK_T_IN, sector, buffer)
    }

    /// Write a sector from a dynamically-sized buffer
    fn write_sector(&mut self, sector: u64, buffer: &[u8]) -> bool {
        if buffer.len() < self.sector_size {
            return false;
        }
        // Need mutable buffer for the request interface
        let mut buf = [0u8; MAX_SECTOR_SIZE];
        buf[..self.sector_size].copy_from_slice(&buffer[..self.sector_size]);
        self.do_request(VIRTIO_BLK_T_OUT, sector, &mut buf[..self.sector_size])
    }

    /// Perform a block request
    fn do_request(&mut self, req_type: u32, sector: u64, buffer: &mut [u8]) -> bool {
        // Use DMA pool for request structures
        // Layout: header (16 bytes), data (sector_size bytes), status (1 byte)
        let header_addr = DMA_POOL_BASE as u64;
        let data_addr = header_addr + 16;
        let status_addr = data_addr + self.sector_size as u64;

        // Write header
        let header = VirtioBlkReqHeader {
            type_: req_type,
            reserved: 0,
            sector,
        };
        unsafe {
            let header_ptr = header_addr as *mut VirtioBlkReqHeader;
            write_volatile(header_ptr, header);
        }

        // For write requests, copy data to DMA buffer
        if req_type == VIRTIO_BLK_T_OUT {
            unsafe {
                let data_ptr = data_addr as *mut u8;
                for (i, &byte) in buffer[..self.sector_size].iter().enumerate() {
                    write_volatile(data_ptr.add(i), byte);
                }
            }
        }

        // Clear status
        unsafe {
            write_volatile(status_addr as *mut u8, 0xFF);
        }

        // Set up descriptors
        // Each request uses 3 descriptors, so we can fit QUEUE_SIZE/3 requests
        // before wrapping. Wrap avail_idx to the number of request slots, then
        // multiply by 3 to get the actual descriptor index.
        let desc_idx = (self.avail_idx % (QUEUE_SIZE / 3)) * 3;

        // Descriptor 0: header (device reads)
        self.write_desc(desc_idx, header_addr, 16, VIRTQ_DESC_F_NEXT, desc_idx + 1);

        // Descriptor 1: data
        let data_flags = if req_type == VIRTIO_BLK_T_IN {
            VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE // Device writes (read operation)
        } else {
            VIRTQ_DESC_F_NEXT // Device reads (write operation)
        };
        self.write_desc(
            desc_idx + 1,
            data_addr,
            self.sector_size as u32,
            data_flags,
            desc_idx + 2,
        );

        // Descriptor 2: status (device writes)
        self.write_desc(desc_idx + 2, status_addr, 1, VIRTQ_DESC_F_WRITE, 0);

        // Add to available ring
        let avail_idx = self.avail_idx;
        let ring_idx = avail_idx % QUEUE_SIZE;

        // Write to avail ring
        unsafe {
            let avail_ring = (self.avail_base + 4 + (ring_idx as usize * 2)) as *mut u16;
            write_volatile(avail_ring, desc_idx);

            // Update avail idx (with memory barrier)
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            let avail_idx_ptr = (self.avail_base + 2) as *mut u16;
            write_volatile(avail_idx_ptr, avail_idx.wrapping_add(1));
        }

        self.avail_idx = avail_idx.wrapping_add(1);

        // Notify device
        self.write_reg(reg::QUEUE_NOTIFY, 0);

        // Wait for completion (poll used ring)
        let expected_used_idx = avail_idx.wrapping_add(1);
        loop {
            unsafe {
                let used_idx = read_volatile((self.used_base + 2) as *const u16);
                if used_idx == expected_used_idx {
                    break;
                }
            }
            core::hint::spin_loop();
        }

        // Acknowledge interrupt
        let int_status = self.read_reg(reg::INTERRUPT_STATUS);
        if int_status != 0 {
            self.write_reg(reg::INTERRUPT_ACK, int_status);
        }

        // Check status
        let status = unsafe { read_volatile(status_addr as *const u8) };

        // For read requests, copy data from DMA buffer
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

    /// Write a descriptor
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

/// Entry point
#[no_mangle]
pub extern "C" fn _start() -> ! {
    debug_print("guest: start\n");

    // Read configuration from VMM over serial
    let config: DeviceConfig = read_config();
    debug_print("guest: config\n");

    // Report configuration
    send_init("config", "input", config.input_sector_size as u64);
    send_init("config", "output", config.output_sector_size as u64);
    send_init("config", "progress", config.progress_percent as u64);

    // Initialize input device with configured sector size
    let mut input = match VirtioBlock::init(
        INPUT_MMIO_BASE,
        INPUT_VQ_BASE,
        config.input_sector_size,
        "input",
    ) {
        Some(dev) => dev,
        None => {
            send_complete("init", 0, false);
            halt();
        }
    };

    // Initialize output device with configured sector size
    let mut output = match VirtioBlock::init(
        OUTPUT_MMIO_BASE,
        OUTPUT_VQ_BASE,
        config.output_sector_size,
        "output",
    ) {
        Some(dev) => dev,
        None => {
            send_complete("init", 0, false);
            halt();
        }
    };

    // Copy data from input to output
    // When sector sizes differ, we need to handle the translation
    let input_sector_size = config.input_sector_size;
    let output_sector_size = config.output_sector_size;

    // Use input capacity as the source of truth for total bytes
    let total_bytes = input.capacity * input_sector_size as u64;
    let total_input_sectors = input.capacity;

    // Allocate buffers
    let mut input_buffer = [0u8; MAX_SECTOR_SIZE];
    let mut output_buffer = [0u8; MAX_SECTOR_SIZE];

    let mut bytes_copied = 0u64;
    let mut errors = 0u64;
    let mut input_sector = 0u64;
    let mut output_sector = 0u64;
    let mut output_buffer_pos = 0usize;

    // Progress tracking
    let progress_percent = config.progress_percent;
    let mut last_reported_percent: u32 = 0;

    debug_print("guest: copy\n");

    // Simple copy loop that handles sector size translation
    while input_sector < total_input_sectors {
        // Read from input
        if !input.read_sector(input_sector, &mut input_buffer) {
            send_error("read", "input", input_sector, 1);
            errors += 1;
            input_sector += 1;
            continue;
        }

        // Copy data to output buffer
        let bytes_read = input_sector_size;
        let mut src_pos = 0usize;

        while src_pos < bytes_read {
            let space_in_output = output_sector_size - output_buffer_pos;
            let bytes_to_copy = core::cmp::min(bytes_read - src_pos, space_in_output);

            // Copy bytes
            for i in 0..bytes_to_copy {
                output_buffer[output_buffer_pos + i] = input_buffer[src_pos + i];
            }

            output_buffer_pos += bytes_to_copy;
            src_pos += bytes_to_copy;

            // If output buffer is full, write it
            if output_buffer_pos >= output_sector_size {
                if !output.write_sector(output_sector, &output_buffer) {
                    send_error("write", "output", output_sector, 1);
                    errors += 1;
                } else {
                    bytes_copied += output_sector_size as u64;
                }
                output_sector += 1;
                output_buffer_pos = 0;
            }
        }

        input_sector += 1;

        // Progress reporting based on configuration
        // progress_percent: 0=every 10 sectors, 1-99=every N%, 100=none
        let current_percent = if total_input_sectors > 0 {
            (input_sector * 100 / total_input_sectors) as u32
        } else {
            100
        };

        let should_report = match progress_percent {
            0 => {
                // Legacy: every 10 sectors or last sector
                input_sector % 10 == 0 || input_sector == total_input_sectors
            }
            100 => {
                // No progress updates
                false
            }
            interval => {
                // Report when crossing a percentage threshold
                let threshold = (current_percent / interval) * interval;
                if threshold > last_reported_percent || input_sector == total_input_sectors {
                    last_reported_percent = threshold;
                    true
                } else {
                    false
                }
            }
        };

        if should_report {
            send_progress("copy", input_sector, total_input_sectors, current_percent);
        }
    }

    // Flush any remaining data in output buffer (partial sector)
    if output_buffer_pos > 0 {
        // Pad with zeros
        for i in output_buffer_pos..output_sector_size {
            output_buffer[i] = 0;
        }
        if !output.write_sector(output_sector, &output_buffer) {
            send_error("write", "output", output_sector, 1);
            errors += 1;
        } else {
            bytes_copied += output_buffer_pos as u64;
        }
    }

    send_complete("copy", bytes_copied, errors == 0);
    debug_print("guest: done\n");
    halt();
}

/// Halt the CPU
fn halt() -> ! {
    unsafe {
        asm!("hlt", options(nomem, nostack));
    }
    loop {
        unsafe {
            asm!("hlt", options(nomem, nostack));
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    send_error("panic", "guest", 0, 0xDEAD);
    halt();
}
