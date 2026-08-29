---
name: verbose-print
description: "Add diagnostic output to guest operations with verbose_print() and debug_print(), and choose correctly between them. Use when adding new code paths to an operation, or when reviewing verbose output coverage."
---

# /verbose-print - Adding Diagnostic Output to Operations

Guidelines for adding verbose_print() calls to instar guest operations for consistent, useful diagnostic output.

## Usage

```
/verbose-print
```

Invoke this skill when adding new code paths to operations, or when reviewing verbose_print coverage.

## Instructions for Claude

When the user invokes this skill, review the operations code and suggest where verbose_print() calls would be beneficial, following the patterns below.

---

## Two Print Functions

Operations have access to two print functions via the call table:

1. **debug_print** - Always prints. Use for:
   - Error conditions (call table magic/version mismatch)
   - Critical failures that need visibility

2. **verbose_print** - Only prints when `--verbose` flag is passed. Use for:
   - Diagnostic tracing (operation lifecycle)
   - Configuration validation results
   - Format detection outcomes
   - Feature discovery notifications
   - Code path selection indicators

---

## When to Add verbose_print() Calls

### Entry/Exit Points
Every operation should have start and done messages:
```rust
(call_table.verbose_print)(b"opname: start\n\0".as_ptr());
// ... operation code ...
(call_table.verbose_print)(b"opname: done\n\0".as_ptr());
```

### Configuration Validation
When checking operation config:
```rust
if config.is_valid() {
    (call_table.verbose_print)(b"opname: config ok\n\0".as_ptr());
} else {
    (call_table.verbose_print)(b"opname: no config\n\0".as_ptr());
}
```

### Major Code Path Selection
When the code takes different branches based on input:
```rust
// Sector size translation
if input_sector_size >= output_sector_size {
    (call_table.verbose_print)(b"copy: input sectors >= output\n\0".as_ptr());
} else {
    (call_table.verbose_print)(b"copy: input sectors < output\n\0".as_ptr());
}

// Format-specific handling
match format {
    ImageFormat::Qcow2 => {
        (call_table.verbose_print)(b"check: checking qcow2\n\0".as_ptr());
    }
    ImageFormat::Raw => {
        (call_table.verbose_print)(b"check: raw format, no metadata\n\0".as_ptr());
    }
    _ => {
        (call_table.verbose_print)(b"check: format not supported\n\0".as_ptr());
    }
}
```

### Feature Detection
When discovering optional features or metadata:
```rust
if backing_offset != 0 && backing_size > 0 {
    (call_table.verbose_print)(b"info: has backing file\n\0".as_ptr());
}

if (incompat & QCOW2_INCOMPAT_EXTERNAL_DATA) != 0 {
    (call_table.verbose_print)(b"info: has external data\n\0".as_ptr());
}
```

### Optional Processing Modes
When optional features are enabled:
```rust
if skip_zeros {
    (call_table.verbose_print)(b"copy: skip zeros enabled\n\0".as_ptr());
}
```

---

## Message Format Guidelines

### Prefix with operation name
Always start messages with the operation name followed by a colon:
- `b"info: ..."`
- `b"copy: ..."`
- `b"check: ..."`

### Use lowercase
Keep messages lowercase for consistency:
- Good: `b"info: found MBR partition table\n\0"`
- Bad: `b"Info: Found MBR Partition Table\n\0"`

### End with newline and null terminator
All strings must be null-terminated and include a newline:
```rust
b"info: message\n\0"
//              ^^-- newline then null
```

### Keep messages concise
Messages appear in serial output; keep them short but descriptive:
- Good: `b"copy: skip zeros enabled\n\0"`
- Too verbose: `b"copy: the skip zeros optimization is now enabled for this copy operation\n\0"`

### Use present tense / participles
Describe what's happening or what was found:
- `"reading header"` not `"will read header"`
- `"detected format"` not `"format has been detected"`
- `"has backing file"` not `"backing file exists"`

---

## What NOT to Add

### Per-iteration output
Don't add verbose_print inside tight loops:
```rust
// BAD - will flood output
for sector in 0..100000 {
    (call_table.verbose_print)(b"copy: processing sector\n\0".as_ptr());
    // ...
}

// GOOD - print once before loop
(call_table.verbose_print)(b"copy: copying sectors\n\0".as_ptr());
for sector in 0..100000 {
    // ...
}
```

### Error conditions
Use debug_print for errors (they should always be visible):
```rust
// GOOD - errors use debug_print
if call_table.magic != CallTable::MAGIC {
    (call_table.debug_print)(b"copy: bad magic\n\0".as_ptr());
    return 0;
}
```

### Redundant messages
Don't repeat information that's already being reported:
```rust
// BAD - send_progress already reports this
(call_table.verbose_print)(b"copy: 50% done\n\0".as_ptr());
```

---

## Current Coverage Reference

**info** (16 calls):
- Entry/exit: start, done
- Header checks: reading header, checking VHD footer, checking ISO 9660
- Partition detection: found MBR/GPT partition table, no partition table (with variants)
- Format detection: detected format
- Format parsing: parsing qcow2, VHDX parsed ok, reading VMDK descriptor
- Feature discovery: has backing file, has external data, found backing format ext

**check** (8 calls):
- Entry/exit: start, done
- Phases: reading header, detected format
- Format handling: raw format no metadata, format not supported, qcow2 check complete

**copy** (9 calls):
- Entry/exit: start, done
- Config: config ok, no config
- Modes: skip zeros enabled, input sectors >= output, input sectors < output
- Phase: copying

---

## Testing verbose_print Coverage

Run with `--verbose` to see all diagnostic output:
```bash
sudo ./target/release/instar info --verbose image.qcow2
sudo ./target/release/instar copy --verbose input.qcow2 output.raw
sudo ./target/release/instar check --verbose image.qcow2
```
