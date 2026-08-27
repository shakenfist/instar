---
name: instar-calltable
description: "Call table API reference for guest operations: the I/O, progress and configuration function pointers the core places at CALL_TABLE_ADDR. Use when writing or debugging operation code that talks to the core."
---

# /instar-calltable - Call Table API Reference

Complete reference for the call table API used by instar operations to communicate with the core.

## Usage

```
/instar-calltable [function]
```

Where `[function]` can be: `io`, `progress`, `config`, or omit for full reference.

## Instructions for Claude

When the user invokes this skill, provide detailed documentation about the call table API. Focus on the specific area if requested.

---

## Overview

The call table is a function pointer table that the core places at `CALL_TABLE_ADDR` (0x18000) before jumping to an operation. Operations use these function pointers to:

- Read/write disk sectors
- Query device properties
- Report progress and errors
- Get operation-specific configuration

## Memory Addresses

```rust
/// Call table location
pub const CALL_TABLE_ADDR: usize = 0x00018000;

/// Operation config location
pub const OPERATION_CONFIG_ADDR: usize = 0x00019000;

/// Max config size
pub const OPERATION_CONFIG_MAX_SIZE: usize = 4096;

/// Where operations are loaded
pub const OPERATION_LOAD_ADDR: usize = 0x00020000;

/// Maximum sector size supported
pub const MAX_SECTOR_SIZE: usize = 65536;
```

## Call Table Structure

```rust
#[repr(C)]
pub struct CallTable {
    /// Magic number: 0x494D4147 ("IMAG")
    pub magic: u32,

    /// ABI version (currently 3)
    pub version: u32,

    // I/O Functions
    pub read_input_sector: unsafe extern "C" fn(u64, *mut u8, usize) -> bool,
    pub write_output_sector: unsafe extern "C" fn(u64, *const u8, usize) -> bool,

    // Device Info Functions
    pub get_input_capacity: unsafe extern "C" fn() -> u64,
    pub get_output_capacity: unsafe extern "C" fn() -> u64,
    pub get_input_sector_size: unsafe extern "C" fn() -> usize,
    pub get_output_sector_size: unsafe extern "C" fn() -> usize,

    // Progress/Messaging Functions
    pub get_progress_interval: unsafe extern "C" fn() -> u32,
    pub send_progress: unsafe extern "C" fn(*const u8, u64, u64, u32),
    pub send_error: unsafe extern "C" fn(*const u8, *const u8, u64, u32),
    pub send_complete: unsafe extern "C" fn(*const u8, u64, bool),
    pub debug_print: unsafe extern "C" fn(*const u8),

    // Configuration Functions
    pub get_operation_config: unsafe extern "C" fn() -> ConfigResult,

    // Info Operation Result (v3+)
    pub send_info_result: unsafe extern "C" fn(
        *const u8, u32, u64, u64, u32, u32, *const u8, *const u8
    ),
}

impl CallTable {
    pub const MAGIC: u32 = 0x494D4147;  // "IMAG"
    pub const VERSION: u32 = 3;
}
```

---

## Accessing the Call Table

```rust
use shared::{CallTable, CALL_TABLE_ADDR};

fn call_table() -> &'static CallTable {
    unsafe { &*(CALL_TABLE_ADDR as *const CallTable) }
}

// Always verify before use
pub extern "C" fn _start() -> u64 {
    let ct = call_table();
    if ct.magic != CallTable::MAGIC || ct.version < CallTable::VERSION {
        return 0;  // Invalid call table
    }
    // Safe to use ct now
}
```

---

## I/O Functions

### read_input_sector

Read a sector from the input device.

```rust
pub read_input_sector: unsafe extern "C" fn(
    sector: u64,      // Sector number (0-indexed)
    buffer: *mut u8,  // Buffer to read into
    length: usize     // Buffer length (should match sector size)
) -> bool;            // true on success
```

**Example:**
```rust
let sector_size = unsafe { (ct.get_input_sector_size)() };
let mut buf = [0u8; 4096];  // Or allocate based on sector_size

let success = unsafe {
    (ct.read_input_sector)(0, buf.as_mut_ptr(), sector_size)
};

if !success {
    // Handle error - sector out of range or I/O failure
}
```

### write_output_sector

Write a sector to the output device.

```rust
pub write_output_sector: unsafe extern "C" fn(
    sector: u64,       // Sector number
    buffer: *const u8, // Data to write
    length: usize      // Data length
) -> bool;             // true on success
```

**Example:**
```rust
let success = unsafe {
    (ct.write_output_sector)(sector_num, data.as_ptr(), data.len())
};
```

**Notes:**
- Output device may be read-only (copy operation without output file)
- Returns false if device is read-only or sector out of range

---

## Device Info Functions

### get_input_capacity / get_output_capacity

Get device capacity in sectors.

```rust
pub get_input_capacity: unsafe extern "C" fn() -> u64;
pub get_output_capacity: unsafe extern "C" fn() -> u64;
```

**Example:**
```rust
let input_sectors = unsafe { (ct.get_input_capacity)() };
let output_sectors = unsafe { (ct.get_output_capacity)() };
```

### get_input_sector_size / get_output_sector_size

Get sector size in bytes.

```rust
pub get_input_sector_size: unsafe extern "C" fn() -> usize;
pub get_output_sector_size: unsafe extern "C" fn() -> usize;
```

**Common values:** 512, 4096

**Example:**
```rust
let in_size = unsafe { (ct.get_input_sector_size)() };
let out_size = unsafe { (ct.get_output_sector_size)() };

// Allocate appropriately-sized buffer
let mut buf = vec![0u8; in_size];  // If using alloc
// Or use a static buffer if sector size is known
```

---

## Progress/Messaging Functions

### get_progress_interval

Get the progress reporting interval.

```rust
pub get_progress_interval: unsafe extern "C" fn() -> u32;
```

**Return values:**
- `0` = Report every ~10% (default)
- `1-99` = Report at this percent interval
- `100` = No progress reporting

### send_progress

Report operation progress.

```rust
pub send_progress: unsafe extern "C" fn(
    operation: *const u8,  // Null-terminated operation name
    current: u64,          // Current position (bytes or sectors)
    total: u64,            // Total size
    percent: u32           // Percentage complete (0-100)
);
```

**Example:**
```rust
let op_name = b"copy\0";
let percent = ((current * 100) / total) as u32;

unsafe {
    (ct.send_progress)(op_name.as_ptr(), current, total, percent);
}
```

### send_error

Report an error.

```rust
pub send_error: unsafe extern "C" fn(
    operation: *const u8,  // Null-terminated operation name
    device: *const u8,     // "input\0" or "output\0"
    sector: u64,           // Sector where error occurred
    status: u32            // Error code/status
);
```

**Example:**
```rust
let op = b"copy\0";
let dev = b"input\0";
unsafe {
    (ct.send_error)(op.as_ptr(), dev.as_ptr(), bad_sector, 1);
}
```

### send_complete

Signal operation completion.

```rust
pub send_complete: unsafe extern "C" fn(
    operation: *const u8,  // Null-terminated operation name
    bytes: u64,            // Bytes processed
    success: bool          // true if operation succeeded
);
```

**Example:**
```rust
let op = b"copy\0";
unsafe {
    (ct.send_complete)(op.as_ptr(), bytes_copied, true);
}
```

### debug_print

Print debug message to VMM console.

```rust
pub debug_print: unsafe extern "C" fn(msg: *const u8);
```

**Example:**
```rust
fn debug(msg: &str) {
    let mut buf = [0u8; 256];
    let len = msg.len().min(255);
    buf[..len].copy_from_slice(&msg.as_bytes()[..len]);
    buf[len] = 0;  // Null terminate!
    unsafe { (call_table().debug_print)(buf.as_ptr()) };
}

debug("Starting operation...");
```

---

## Configuration Functions

### get_operation_config

Get operation-specific configuration.

```rust
pub get_operation_config: unsafe extern "C" fn() -> ConfigResult;

#[repr(C)]
pub struct ConfigResult {
    pub ptr: *const u8,  // Pointer to config data
    pub len: usize,      // Length in bytes
}
```

**Example (copy operation):**
```rust
use shared::CopyConfig;

let config_result = unsafe { (ct.get_operation_config)() };
if config_result.len >= core::mem::size_of::<CopyConfig>() {
    let config = unsafe { &*(config_result.ptr as *const CopyConfig) };
    if config.is_valid() {
        if config.should_verify() {
            // Verify after copy
        }
        if config.should_skip_zeros() {
            // Skip zero sectors
        }
    }
}
```

### send_info_result (v3+)

Send image format detection results (info operation).

```rust
pub send_info_result: unsafe extern "C" fn(
    format: *const u8,           // Format name (null-terminated)
    version: u32,                // Format version
    virtual_size: u64,           // Virtual disk size
    actual_size: u64,            // Actual file size
    cluster_size: u32,           // Cluster size (0 if N/A)
    flags: u32,                  // Feature flags
    backing_file: *const u8,     // Backing file path (null-terminated)
    external_data_file: *const u8 // External data file (null-terminated)
);
```

---

## Pre-defined Config Structures

### CopyConfig

```rust
#[repr(C)]
pub struct CopyConfig {
    pub magic: u32,         // 0x434F5059 ("COPY")
    pub flags: u32,
    pub start_sector: u64,  // 0 = from beginning
    pub sector_count: u64,  // 0 = all remaining
}

impl CopyConfig {
    pub const MAGIC: u32 = 0x434F5059;
    pub const FLAG_VERIFY: u32 = 1 << 0;
    pub const FLAG_SKIP_ZEROS: u32 = 1 << 1;
}
```

### InfoConfig

```rust
#[repr(C)]
pub struct InfoConfig {
    pub magic: u32,  // 0x494E464F ("INFO")
    pub flags: u32,
}

impl InfoConfig {
    pub const MAGIC: u32 = 0x494E464F;
    pub const FLAG_DETAILED: u32 = 1 << 0;
    pub const FLAG_SECURITY_CHECK: u32 = 1 << 1;
}
```

---

## Complete Example

```rust
#![no_std]
#![no_main]

use shared::{CallTable, CALL_TABLE_ADDR};

fn call_table() -> &'static CallTable {
    unsafe { &*(CALL_TABLE_ADDR as *const CallTable) }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> u64 {
    let ct = call_table();

    // Verify call table
    if ct.magic != CallTable::MAGIC {
        return 0;
    }

    // Get device info
    let capacity = unsafe { (ct.get_input_capacity)() };
    let sector_size = unsafe { (ct.get_input_sector_size)() };

    // Read first sector
    let mut header = [0u8; 512];
    let ok = unsafe {
        (ct.read_input_sector)(0, header.as_mut_ptr(), 512)
    };

    if !ok {
        let op = b"myop\0";
        let dev = b"input\0";
        unsafe { (ct.send_error)(op.as_ptr(), dev.as_ptr(), 0, 1) };
        return 0;
    }

    // Process data...
    let bytes_processed = capacity * sector_size as u64;

    // Signal completion
    let op = b"myop\0";
    unsafe { (ct.send_complete)(op.as_ptr(), bytes_processed, true) };

    bytes_processed
}
```
