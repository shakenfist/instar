//! Memory layout constants for the bare-metal guest.
//!
//! These must match the VMM's memory layout configuration.

// MMIO addresses are outside guest memory (256MB) so KVM generates MMIO exits
pub const INPUT_MMIO_BASE: usize = 0x10000000;
pub const OUTPUT_MMIO_BASE: usize = 0x10001000;

// Virtqueue and DMA regions are inside guest memory (8MB)
pub const INPUT_VQ_BASE: usize = 0x100000;
pub const OUTPUT_VQ_BASE: usize = 0x110000;
pub const DMA_POOL_BASE: usize = 0x200000;

// Maximum sector size we support (for DMA buffer allocation)
pub const MAX_SECTOR_SIZE: usize = 65536; // 64KB
