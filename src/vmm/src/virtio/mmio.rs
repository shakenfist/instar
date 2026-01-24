//! Virtio MMIO register definitions and handling.
//!
//! Per VIRTIO 1.1 specification, section 4.2.2.
//!
//! Register constants are imported from the shared crate to ensure consistency
//! between guest and host code. Local re-exports provide the u32 type expected
//! by the VMM's MMIO handling code.

use shared::virtio as shared_virtio;

/// MMIO register offsets (re-exported as u32 for MMIO handling).
pub mod reg {
    use super::shared_virtio::reg as shared_reg;

    pub const MAGIC_VALUE: u32 = shared_reg::MAGIC_VALUE as u32;
    pub const VERSION: u32 = shared_reg::VERSION as u32;
    pub const DEVICE_ID: u32 = shared_reg::DEVICE_ID as u32;
    pub const VENDOR_ID: u32 = shared_reg::VENDOR_ID as u32;
    pub const DEVICE_FEATURES: u32 = shared_reg::DEVICE_FEATURES as u32;
    pub const DEVICE_FEATURES_SEL: u32 = shared_reg::DEVICE_FEATURES_SEL as u32;
    pub const DRIVER_FEATURES: u32 = shared_reg::DRIVER_FEATURES as u32;
    pub const DRIVER_FEATURES_SEL: u32 = shared_reg::DRIVER_FEATURES_SEL as u32;
    pub const QUEUE_SEL: u32 = shared_reg::QUEUE_SEL as u32;
    pub const QUEUE_NUM_MAX: u32 = shared_reg::QUEUE_NUM_MAX as u32;
    pub const QUEUE_NUM: u32 = shared_reg::QUEUE_NUM as u32;
    pub const QUEUE_READY: u32 = shared_reg::QUEUE_READY as u32;
    pub const QUEUE_NOTIFY: u32 = shared_reg::QUEUE_NOTIFY as u32;
    pub const INTERRUPT_STATUS: u32 = shared_reg::INTERRUPT_STATUS as u32;
    pub const INTERRUPT_ACK: u32 = shared_reg::INTERRUPT_ACK as u32;
    pub const STATUS: u32 = shared_reg::STATUS as u32;
    pub const QUEUE_DESC_LOW: u32 = shared_reg::QUEUE_DESC_LOW as u32;
    pub const QUEUE_DESC_HIGH: u32 = shared_reg::QUEUE_DESC_HIGH as u32;
    pub const QUEUE_DRIVER_LOW: u32 = shared_reg::QUEUE_DRIVER_LOW as u32;
    pub const QUEUE_DRIVER_HIGH: u32 = shared_reg::QUEUE_DRIVER_HIGH as u32;
    pub const QUEUE_DEVICE_LOW: u32 = shared_reg::QUEUE_DEVICE_LOW as u32;
    pub const QUEUE_DEVICE_HIGH: u32 = shared_reg::QUEUE_DEVICE_HIGH as u32;
    pub const CONFIG_GENERATION: u32 = shared_reg::CONFIG_GENERATION as u32;
    pub const CONFIG: u32 = shared_reg::CONFIG as u32;
}

// Re-export shared constants directly
pub use shared_virtio::DEVICE_ID_BLOCK;
pub use shared_virtio::MAGIC;
pub use shared_virtio::QUEUE_SIZE_MAX;
pub use shared_virtio::VENDOR_ID;
pub use shared_virtio::VERSION;

/// Device status bits (re-exported from shared crate for API completeness)
#[allow(unused_imports)]
pub mod status {
    pub use shared::virtio::status::*;
}

/// Block device feature bits (re-exported from shared crate)
#[allow(unused_imports)]
pub mod features {
    pub use shared::virtio::features::*;
}

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
