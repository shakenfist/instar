---
name: instar-new-op
description: "Scaffold a new instar guest operation binary under src/operations/, with its main.rs, Cargo.toml, linker script and cargo configuration. Use when adding a new operation to the call table."
---

# /instar-new-op - Scaffold a New Instar Operation

Create a new instar operation binary that runs inside the sandboxed VM.

## Usage

```
/instar-new-op <operation-name> [description]
```

## What This Does

Creates a complete operation skeleton under `src/operations/<name>/` with:
- `src/main.rs` - Entry point with call table setup, panic handler, and operation structure
- `Cargo.toml` - Dependencies and release profile configuration
- `linker.ld` - Linker script for loading at 0x20000
- `.cargo/config.toml` - Build target configuration for `x86_64-unknown-none`

## Instructions for Claude

When the user invokes this skill, create a new operation with the following structure:

### 1. Create Directory Structure

```
src/operations/<name>/
├── .cargo/
│   └── config.toml
├── src/
│   └── main.rs
├── Cargo.toml
└── linker.ld
```

### 2. File Templates

#### `src/operations/<name>/Cargo.toml`

```toml
[package]
name = "<name>"
version = "0.1.0"
edition = "2021"
description = "<description or 'Instar <name> operation'>"

[dependencies]
shared = { path = "../../shared" }

[profile.release]
panic = "abort"
opt-level = "z"
lto = true
```

#### `src/operations/<name>/linker.ld`

```ld
/* Linker script for instar operations */
/* Operations are loaded at OPERATION_LOAD_ADDR (0x20000) */

ENTRY(_start)

SECTIONS
{
    . = 0x20000;

    .text : {
        *(.text._start)
        *(.text .text.*)
    }

    .rodata : {
        *(.rodata .rodata.*)
    }

    .data : {
        *(.data .data.*)
    }

    .bss : {
        *(.bss .bss.*)
    }

    /DISCARD/ : {
        *(.eh_frame)
        *(.note.*)
    }
}
```

#### `src/operations/<name>/.cargo/config.toml`

```toml
[build]
target = "x86_64-unknown-none"

[target.x86_64-unknown-none]
rustflags = [
    "-C", "link-arg=-Toperations/<name>/linker.ld",
    "-C", "relocation-model=static"
]

[unstable]
build-std = ["core"]
build-std-features = ["compiler-builtins-mem"]
```

#### `src/operations/<name>/src/main.rs`

```rust
//! Instar <name> operation.
//!
//! <description>

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use shared::{CallTable, CALL_TABLE_ADDR};

/// Get the call table from the known address.
fn call_table() -> &'static CallTable {
    unsafe { &*(CALL_TABLE_ADDR as *const CallTable) }
}

/// Debug print helper.
fn debug(msg: &str) {
    // Create a null-terminated buffer on the stack
    let mut buf = [0u8; 256];
    let len = msg.len().min(255);
    buf[..len].copy_from_slice(&msg.as_bytes()[..len]);
    buf[len] = 0;
    unsafe { (call_table().debug_print)(buf.as_ptr()) };
}

/// Entry point called by the core.
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> u64 {
    // Verify call table
    let ct = call_table();
    if ct.magic != CallTable::MAGIC || ct.version < CallTable::VERSION {
        return 0;
    }

    debug("<Name> operation starting");

    // TODO: Implement operation logic here
    //
    // Available call table functions:
    //   ct.read_input_sector(sector, buf_ptr, buf_len) -> bool
    //   ct.write_output_sector(sector, buf_ptr, buf_len) -> bool
    //   ct.get_input_capacity() -> u64
    //   ct.get_output_capacity() -> u64
    //   ct.get_input_sector_size() -> usize
    //   ct.get_output_sector_size() -> usize
    //   ct.get_progress_interval() -> u32
    //   ct.send_progress(name_ptr, current, total, percent)
    //   ct.send_error(op_ptr, device_ptr, sector, status)
    //   ct.send_complete(name_ptr, bytes, success)
    //   ct.debug_print(msg_ptr)
    //   ct.get_operation_config() -> ConfigResult

    let bytes_processed: u64 = 0;

    // Send completion
    let op_name = b"<name>\0";
    unsafe {
        (ct.send_complete)(op_name.as_ptr(), bytes_processed, true);
    }

    bytes_processed
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // Try to report the panic
    let ct = call_table();
    if ct.magic == CallTable::MAGIC {
        let msg = b"PANIC in <name> operation\0";
        unsafe { (ct.debug_print)(msg.as_ptr()) };

        // If we have location info, print it
        if let Some(location) = info.location() {
            let mut buf = [0u8; 128];
            let file = location.file().as_bytes();
            let len = file.len().min(100);
            buf[..len].copy_from_slice(&file[..len]);
            buf[len] = 0;
            unsafe { (ct.debug_print)(buf.as_ptr()) };
        }
    }
    loop {
        core::hint::spin_loop();
    }
}
```

### 3. After Scaffolding

1. **Edit `src/main.rs`** to implement the operation logic
2. **If operation needs config**, add a config struct to `src/shared/src/lib.rs`:
   ```rust
   #[repr(C)]
   #[derive(Clone, Copy)]
   pub struct <Name>Config {
       pub magic: u32,
       pub flags: u32,
       // ... operation-specific fields
   }
   ```
3. **Build the operation**:
   ```bash
   cd src/operations/<name>
   cargo build --release
   ```
4. **Register in VMM** by adding the operation to the VMM's operation loading logic

### 4. Common Patterns

#### Reading Input Sectors

```rust
let sector_size = unsafe { (ct.get_input_sector_size)() };
let mut buf = [0u8; 4096]; // or use sector_size
let success = unsafe { (ct.read_input_sector)(sector_num, buf.as_mut_ptr(), sector_size) };
```

#### Writing Output Sectors

```rust
let success = unsafe { (ct.write_output_sector)(sector_num, buf.as_ptr(), buf.len()) };
```

#### Progress Reporting

```rust
let op_name = b"<name>\0";
let interval = unsafe { (ct.get_progress_interval)() };
// Report progress every `interval` percent (or use your own logic)
unsafe { (ct.send_progress)(op_name.as_ptr(), current, total, percent) };
```

#### Error Reporting

```rust
let op_name = b"<name>\0";
let device = b"input\0"; // or b"output\0"
unsafe { (ct.send_error)(op_name.as_ptr(), device.as_ptr(), sector, status_code) };
```

## Example Invocations

```
/instar-new-op checksum "Calculate checksums of disk images"
/instar-new-op convert "Convert between disk image formats"
/instar-new-op verify "Verify disk image integrity"
```
