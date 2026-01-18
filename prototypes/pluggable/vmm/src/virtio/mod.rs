//! Virtio device emulation for the VMM.
//!
//! Implements virtio-block devices with MMIO transport and configurable
//! sector sizes.

mod block;
mod mmio;

pub use block::VirtioBlockDevice;
