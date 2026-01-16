//! Virtio device emulation for the VMM.
//!
//! Implements virtio-block devices with MMIO transport.

mod block;
mod mmio;

pub use block::VirtioBlockDevice;
