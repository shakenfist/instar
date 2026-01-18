//! Guest infrastructure (infra).
//!
//! This module provides the fundamental building blocks for guest operations:
//! - Memory layout constants
//! - Virtio block device abstraction
//! - Serial communication with the VMM
//!
//! Operations use these primitives to implement their specific functionality.

pub mod mem;
pub mod serial;
pub mod virtio;

pub use mem::{
    DMA_POOL_BASE, INPUT_MMIO_BASE, INPUT_VQ_BASE, MAX_SECTOR_SIZE, OUTPUT_MMIO_BASE,
    OUTPUT_VQ_BASE,
};
pub use serial::{debug_print, read_config, send_complete, send_error, send_init, send_progress};
pub use serial::{DeviceConfig, Operation};
pub use virtio::VirtioBlock;
