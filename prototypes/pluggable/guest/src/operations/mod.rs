//! Pluggable operations for the guest.
//!
//! Operations implement specific functionality (copy, info, transcode, etc.)
//! using the core virtio and serial infrastructure. Each operation receives
//! initialized devices and configuration, then performs its work.
//!
//! # Adding a new operation
//!
//! 1. Create a new module (e.g., `info.rs`)
//! 2. Implement the `GuestOperation` trait
//! 3. Add the operation to the `Operation` enum in `core/serial.rs`
//! 4. Register it in `run_operation()` below

pub mod copy;

use crate::infra::{DeviceConfig, Operation, VirtioBlock};

/// Result of an operation
pub struct OperationResult {
    /// Number of bytes processed
    pub bytes_processed: u64,
    /// Whether the operation completed successfully
    pub success: bool,
}

/// Trait for pluggable guest operations.
///
/// Operations receive initialized virtio devices and configuration,
/// then perform their specific work. The core handles device setup
/// and teardown.
pub trait GuestOperation {
    /// Name of this operation (for logging and messages)
    fn name(&self) -> &'static str;

    /// Execute the operation.
    ///
    /// # Arguments
    /// * `input` - The input virtio block device
    /// * `output` - The output virtio block device (may not be used by all ops)
    /// * `config` - Configuration from the VMM
    ///
    /// # Returns
    /// Result indicating bytes processed and success status
    fn execute(
        &self,
        input: &mut VirtioBlock,
        output: &mut VirtioBlock,
        config: &DeviceConfig,
    ) -> OperationResult;
}

/// Run the operation specified in the configuration.
///
/// This is the main dispatcher that routes to the appropriate operation
/// implementation based on the config.
pub fn run_operation(
    input: &mut VirtioBlock,
    output: &mut VirtioBlock,
    config: &DeviceConfig,
) -> OperationResult {
    match config.operation {
        Operation::Copy => {
            let op = copy::CopyOperation;
            op.execute(input, output, config)
        }
        Operation::Info => {
            // Placeholder for future info operation
            // For now, just report success with input capacity
            OperationResult {
                bytes_processed: input.capacity_bytes(),
                success: true,
            }
        }
    }
}
