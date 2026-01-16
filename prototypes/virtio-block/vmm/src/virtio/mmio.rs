//! Virtio MMIO register definitions and handling.
//!
//! Per VIRTIO 1.1 specification, section 4.2.2.

/// MMIO register offsets
pub mod reg {
    pub const MAGIC_VALUE: u32 = 0x000;
    pub const VERSION: u32 = 0x004;
    pub const DEVICE_ID: u32 = 0x008;
    pub const VENDOR_ID: u32 = 0x00C;
    pub const DEVICE_FEATURES: u32 = 0x010;
    pub const DEVICE_FEATURES_SEL: u32 = 0x014;
    pub const DRIVER_FEATURES: u32 = 0x020;
    pub const DRIVER_FEATURES_SEL: u32 = 0x024;
    pub const QUEUE_SEL: u32 = 0x030;
    pub const QUEUE_NUM_MAX: u32 = 0x034;
    pub const QUEUE_NUM: u32 = 0x038;
    pub const QUEUE_READY: u32 = 0x044;
    pub const QUEUE_NOTIFY: u32 = 0x050;
    pub const INTERRUPT_STATUS: u32 = 0x060;
    pub const INTERRUPT_ACK: u32 = 0x064;
    pub const STATUS: u32 = 0x070;
    pub const QUEUE_DESC_LOW: u32 = 0x080;
    pub const QUEUE_DESC_HIGH: u32 = 0x084;
    pub const QUEUE_DRIVER_LOW: u32 = 0x090;
    pub const QUEUE_DRIVER_HIGH: u32 = 0x094;
    pub const QUEUE_DEVICE_LOW: u32 = 0x0A0;
    pub const QUEUE_DEVICE_HIGH: u32 = 0x0A4;
    pub const CONFIG_GENERATION: u32 = 0x0FC;
    pub const CONFIG: u32 = 0x100;
}

/// Magic value for virtio MMIO devices ("virt")
pub const MAGIC: u32 = 0x74726976;

/// Version (2 = modern virtio)
pub const VERSION: u32 = 2;

/// Device ID for block device
pub const DEVICE_ID_BLOCK: u32 = 2;

/// Our vendor ID
pub const VENDOR_ID: u32 = 0x00001AF4; // Red Hat

/// Device status bits (defined for completeness per VIRTIO 1.1 spec)
#[allow(dead_code)]
pub mod status {
    pub const ACKNOWLEDGE: u8 = 1;
    pub const DRIVER: u8 = 2;
    pub const DRIVER_OK: u8 = 4;
    pub const FEATURES_OK: u8 = 8;
    pub const DEVICE_NEEDS_RESET: u8 = 64;
    pub const FAILED: u8 = 128;
}

/// Block device feature bits (defined for completeness per VIRTIO 1.1 spec)
#[allow(dead_code)]
pub mod features {
    pub const VIRTIO_BLK_F_SIZE_MAX: u64 = 1 << 1;
    pub const VIRTIO_BLK_F_SEG_MAX: u64 = 1 << 2;
    pub const VIRTIO_BLK_F_RO: u64 = 1 << 5;
    pub const VIRTIO_BLK_F_BLK_SIZE: u64 = 1 << 6;
    pub const VIRTIO_BLK_F_FLUSH: u64 = 1 << 9;
    pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;
    pub const VIRTIO_F_RING_PACKED: u64 = 1 << 34;
}

/// Maximum queue size
pub const QUEUE_SIZE_MAX: u16 = 256;

/// Virtqueue state
#[derive(Debug, Default)]
pub struct VirtqueueState {
    pub num: u16,
    pub ready: bool,
    pub desc_addr: u64,
    pub driver_addr: u64,
    pub device_addr: u64,
    pub last_avail_idx: u16,
}

/// MMIO device state
#[derive(Debug, Default)]
pub struct MmioState {
    pub device_features_sel: u32,
    pub driver_features_sel: u32,
    pub driver_features: u64,
    pub queue_sel: u32,
    pub status: u8,
    pub interrupt_status: u32,
    pub queues: [VirtqueueState; 1], // Block device has 1 queue
    pub queue_notify_pending: bool,
}

impl MmioState {
    pub fn current_queue(&self) -> &VirtqueueState {
        &self.queues[self.queue_sel as usize % self.queues.len()]
    }

    pub fn current_queue_mut(&mut self) -> &mut VirtqueueState {
        let idx = self.queue_sel as usize % self.queues.len();
        &mut self.queues[idx]
    }

    pub fn reset(&mut self) {
        *self = Self::default();
    }
}
