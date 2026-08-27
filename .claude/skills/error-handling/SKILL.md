---
name: error-handling
description: "Consistent error reporting in instar: every error reported, propagated to main(), and described with context. Use when adding error handling to an operation or to host code, or when reviewing error propagation."
---

# /error-handling - Consistent Error Reporting in Instar

Guidelines for ensuring all error conditions in instar return proper error codes with descriptive messages.

## Usage

```
/error-handling
```

Invoke this skill when adding new error handling code, or when reviewing code for proper error propagation.

## Instructions for Claude

When the user invokes this skill, review error handling in the specified code and ensure it follows the patterns below.

---

## Core Principles

1. **Every error must be reported** - No silent failures
2. **Errors must propagate to main()** - Use `?` operator or explicit `return Err()`
3. **Error messages must be descriptive** - Include context about what failed
4. **Never use std::process::exit()** - Return errors instead and let main() exit

---

## VMM Error Patterns

### Function Return Types

All operation functions should return `Result<(), Box<dyn std::error::Error>>`:

```rust
fn run_info(args: InfoArgs, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    // ...
}
```

### Validation Errors

When validating input, return descriptive errors:

```rust
// GOOD: Returns error with context
if !args.sector_size.is_power_of_two() {
    return Err(format!(
        "sector size must be a power of 2, 512 to {} (got {})",
        MAX_SECTOR_SIZE, args.sector_size
    ).into());
}

// BAD: Uses exit (bypasses main error handling)
if !args.sector_size.is_power_of_two() {
    eprintln!("Error: invalid sector size");
    std::process::exit(1);  // DON'T DO THIS
}
```

### VM Exit Error Tracking

VM loops must track errors and return them after cleanup:

```rust
// Track VM errors - if set, we return an error instead of Ok(())
let mut vm_error: Option<String> = None;

loop {
    match vcpu.run()? {
        VcpuExit::Hlt => {
            // Normal exit
            break;
        }
        VcpuExit::Shutdown => {
            vmm_stats.lock().unwrap().record_shutdown();
            eprintln!("\n--- VM Shutdown (triple fault?) ---");
            // ... diagnostic output ...
            vm_error = Some("VM shutdown (triple fault)".to_string());
            break;
        }
        VcpuExit::FailEntry(reason, cpu) => {
            vmm_stats.lock().unwrap().record_fail_entry();
            eprintln!("VM Entry Failed! reason=0x{:x}, cpu={}", reason, cpu);
            vm_error = Some(format!("VM entry failed: reason=0x{:x}, cpu={}", reason, cpu));
            break;
        }
        exit => {
            vmm_stats.lock().unwrap().record_unknown();
            eprintln!("Unexpected VM exit: {:?}", exit);
            vm_error = Some(format!("unexpected VM exit: {:?}", exit));
            break;
        }
    }
}

// Cleanup
if let Some(mut thread) = io_thread {
    thread.stop();
}

// Return error if VM crashed or failed
if let Some(error) = vm_error {
    return Err(error.into());
}

Ok(())
```

### Chain Discovery Errors

When calling functions that return Result, propagate or convert errors:

```rust
// GOOD: Propagate with context
match discover_backing_chain(input_path, args.sector_size, &security_config) {
    Ok(chain) => {
        print_backing_chain(&chain);
        return Ok(());
    }
    Err(e) => {
        return Err(format!("error discovering backing chain: {}", e).into());
    }
}

// ALSO GOOD: Use ? operator when context isn't needed
let chain = discover_backing_chain(input_path, args.sector_size, &security_config)?;
```

---

## Guest Operation Error Patterns

Guest operations (no_std) use the call table for error reporting:

### Critical Errors (Always Print)

Use `debug_print` for errors that should always be visible:

```rust
if call_table.magic != CallTable::MAGIC {
    (call_table.debug_print)(b"info: bad magic\n\0".as_ptr());
    return 0;
}
```

### Error Messages via Protocol

Use `send_error` for operation-specific errors:

```rust
if !(call_table.read_input_sector)(0, 0, buffer.as_mut_ptr(), input_sector_size) {
    (call_table.send_error)(b"info\0".as_ptr(), b"input\0".as_ptr(), 0, 1);
    return 0;
}
```

### Panic Handler

Ensure panics report errors before halting:

```rust
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    unsafe {
        let call_table = get_call_table();
        if call_table.magic == CallTable::MAGIC {
            (call_table.send_error)(b"panic\0".as_ptr(), b"info\0".as_ptr(), 0, 0xDEAD);
        }
    }
    loop {
        core::hint::spin_loop();
    }
}
```

---

## Error Types

Use the structured error types in `error.rs`:

- `VmmError` - Top-level VMM errors
- `KvmError` - KVM-specific errors
- `VirtioError` - Virtio device errors
- `ConfigError` - Configuration validation errors

Example:

```rust
use crate::error::{VmmError, ConfigError};

fn validate_something() -> Result<(), VmmError> {
    if something_wrong {
        return Err(ConfigError::InvalidSectorSize {
            value: 256,
            min: 512,
            max: 65536,
        }.into());
    }
    Ok(())
}
```

---

## Checklist for New Code

When adding new code, verify:

- [ ] All error conditions return `Err()` or use `?`
- [ ] No `std::process::exit()` calls
- [ ] VM loop handlers set `vm_error` on failure
- [ ] Error messages include relevant context (values, file paths, etc.)
- [ ] Cleanup code runs before error return
- [ ] Guest panic handlers call `send_error`

---

## Testing Error Paths

When writing tests, verify error behavior:

```rust
#[test]
fn test_invalid_sector_size() {
    // This should return an error, not panic or exit
    let result = run_info(InfoArgs { sector_size: 100, ..Default::default() }, false);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("sector size"));
}
```
