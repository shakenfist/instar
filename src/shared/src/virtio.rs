//! Virtio MMIO register definitions.
//!
//! Per VIRTIO 1.1 specification, section 4.2.2 (MMIO Device Register Layout).
//!
//! These definitions are shared between the guest (core) and host (VMM) to
//! ensure consistency in register offsets and magic values.

/// MMIO register offsets.
///
/// All values are byte offsets from the device MMIO base address.
/// Defined as u64 for maximum compatibility - callers can cast to
/// their preferred type (usize for pointer math, u32 for MMIO indexing).
pub mod reg {
    pub const MAGIC_VALUE: u64 = 0x000;
    pub const VERSION: u64 = 0x004;
    pub const DEVICE_ID: u64 = 0x008;
    pub const VENDOR_ID: u64 = 0x00C;
    pub const DEVICE_FEATURES: u64 = 0x010;
    pub const DEVICE_FEATURES_SEL: u64 = 0x014;
    pub const DRIVER_FEATURES: u64 = 0x020;
    pub const DRIVER_FEATURES_SEL: u64 = 0x024;
    pub const QUEUE_SEL: u64 = 0x030;
    pub const QUEUE_NUM_MAX: u64 = 0x034;
    pub const QUEUE_NUM: u64 = 0x038;
    pub const QUEUE_READY: u64 = 0x044;
    pub const QUEUE_NOTIFY: u64 = 0x050;
    pub const INTERRUPT_STATUS: u64 = 0x060;
    pub const INTERRUPT_ACK: u64 = 0x064;
    pub const STATUS: u64 = 0x070;
    pub const QUEUE_DESC_LOW: u64 = 0x080;
    pub const QUEUE_DESC_HIGH: u64 = 0x084;
    pub const QUEUE_DRIVER_LOW: u64 = 0x090;
    pub const QUEUE_DRIVER_HIGH: u64 = 0x094;
    pub const QUEUE_DEVICE_LOW: u64 = 0x0A0;
    pub const QUEUE_DEVICE_HIGH: u64 = 0x0A4;
    pub const CONFIG_GENERATION: u64 = 0x0FC;
    pub const CONFIG: u64 = 0x100;
}

/// Device status bits per VIRTIO 1.1 spec.
pub mod status {
    pub const ACKNOWLEDGE: u8 = 1;
    pub const DRIVER: u8 = 2;
    pub const DRIVER_OK: u8 = 4;
    pub const FEATURES_OK: u8 = 8;
    pub const DEVICE_NEEDS_RESET: u8 = 64;
    pub const FAILED: u8 = 128;
}

/// Block device feature bits per VIRTIO 1.1 spec.
pub mod features {
    pub const VIRTIO_BLK_F_SIZE_MAX: u64 = 1 << 1;
    pub const VIRTIO_BLK_F_SEG_MAX: u64 = 1 << 2;
    pub const VIRTIO_BLK_F_RO: u64 = 1 << 5;
    pub const VIRTIO_BLK_F_BLK_SIZE: u64 = 1 << 6;
    pub const VIRTIO_BLK_F_FLUSH: u64 = 1 << 9;
    pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;
    pub const VIRTIO_F_RING_PACKED: u64 = 1 << 34;
}

/// Magic value for virtio MMIO devices ("virt" in little-endian).
pub const MAGIC: u32 = 0x74726976;

/// Version (2 = modern virtio per VIRTIO 1.1 spec).
pub const VERSION: u32 = 2;

/// Device ID for block device.
pub const DEVICE_ID_BLOCK: u32 = 2;

/// Vendor ID (Red Hat).
pub const VENDOR_ID: u32 = 0x00001AF4;

/// Maximum queue size.
pub const QUEUE_SIZE_MAX: u16 = 256;

/// Block request types.
pub mod request_type {
    pub const IN: u32 = 0; // Read
    pub const OUT: u32 = 1; // Write
    pub const FLUSH: u32 = 4;
}

/// Block request status values.
pub mod request_status {
    pub const OK: u8 = 0;
    pub const IOERR: u8 = 1;
    pub const UNSUPP: u8 = 2;
}

/// Virtqueue descriptor flags.
pub mod desc_flags {
    pub const NEXT: u16 = 1;
    pub const WRITE: u16 = 2;
}
