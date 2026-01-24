# /imago-debug - Troubleshooting Imago Operations

Diagnose and fix common issues when developing imago guest operations.

## Usage

```
/imago-debug [issue]
```

Where `[issue]` can be: `build`, `boot`, `virtio`, `calltable`, `panic`, or omit for general guidance.

## Instructions for Claude

When the user invokes this skill, help diagnose their issue. Ask clarifying questions if the issue type isn't clear from context.

---

## Build Issues

### "error: requires nightly compiler"

**Cause:** Using `build-std` requires nightly features.

**Fix:** Ensure `.cargo/config.toml` has:
```toml
[unstable]
build-std = ["core"]
build-std-features = ["compiler-builtins-mem"]
```

And build with: `cargo +nightly build --release`

### "undefined reference to `memcpy`/`memset`"

**Cause:** Missing compiler builtins for `no_std`.

**Fix:** Add to `.cargo/config.toml`:
```toml
build-std-features = ["compiler-builtins-mem"]
```

### "relocation truncated to fit"

**Cause:** Code/data doesn't fit at load address, or wrong relocation model.

**Fix:** Check linker script and ensure:
```toml
[target.x86_64-unknown-none]
rustflags = [
    "-C", "link-arg=-Toperations/<name>/linker.ld",
    "-C", "relocation-model=static"
]
```

### Binary too large

**Cause:** Debug info, missing LTO, or unoptimized build.

**Fix:** Ensure `Cargo.toml` has:
```toml
[profile.release]
panic = "abort"
opt-level = "z"    # Optimize for size
lto = true         # Link-time optimization
```

---

## Boot/Startup Issues

### Guest doesn't start / VMM hangs

**Check list:**
1. Is `_start` exported correctly?
   ```rust
   #[unsafe(no_mangle)]
   pub extern "C" fn _start() -> u64 {
   ```

2. Is `_start` in the `.text._start` section?
   ```
   .text : {
       *(.text._start)   <- Must be first
       *(.text .text.*)
   }
   ```

3. Is the binary loaded at the correct address (0x20000)?

4. Is the VMM finding and loading the operation binary?

### "VM entry failed"

**Cause:** Invalid guest state or memory mapping.

**Check:**
- Guest memory is properly mapped
- Entry point is within mapped memory
- No overlapping memory regions

### Guest immediately panics

**Cause:** Call table not initialized or magic mismatch.

**Debug:** Add early debug output:
```rust
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> u64 {
    // First, write something to serial port directly
    unsafe {
        core::ptr::write_volatile(0x3f8 as *mut u8, b'!');
    }

    let ct = call_table();
    // Check magic before using any functions
    if ct.magic != CallTable::MAGIC {
        // Magic wrong - call table not initialized
        return 0;
    }
    // ...
}
```

---

## Virtio Issues

### Virtio device not ready

**Symptoms:** Queue operations fail, no I/O happens.

**Check driver initialization sequence:**
1. Read MAGIC_VALUE (0x74726976)
2. Read VERSION (must be 2)
3. Read DEVICE_ID (2 for block)
4. Reset device (write 0 to STATUS)
5. Set ACKNOWLEDGE bit
6. Set DRIVER bit
7. Negotiate features
8. Set FEATURES_OK bit
9. Read back FEATURES_OK (must be set)
10. Configure queues
11. Set DRIVER_OK bit

### I/O operations fail silently

**Debug virtqueue state:**
```rust
debug("Checking queue state...");
// Print desc_addr, driver_addr, device_addr
// Verify addresses are within guest memory
// Check queue is marked ready
```

### Sector read/write returns false

**Possible causes:**
1. Sector number out of range
2. Buffer address invalid (not in guest memory)
3. Buffer length incorrect
4. Device is read-only (for writes)

**Debug:**
```rust
let capacity = unsafe { (ct.get_input_capacity)() };
debug_u64("Input capacity:", capacity);

let sector_size = unsafe { (ct.get_input_sector_size)() };
debug_usize("Sector size:", sector_size);
```

---

## Call Table Issues

### Call table magic is wrong

**Cause:** Core hasn't initialized the call table yet.

**Fix:** Ensure operation is loaded AFTER core sets up call table.

### "version < CallTable::VERSION"

**Cause:** Core and operation built with different shared crate versions.

**Fix:** Rebuild both core and operation with same shared crate.

### Function pointer is null

**Cause:** Call table field not initialized by core.

**Check:** Verify core initializes all call table fields before jumping to operation.

---

## Panic Debugging

### Getting panic information

Operations run in `no_std`, so panics don't print by default. Add a panic handler:

```rust
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    let ct = call_table();
    if ct.magic == CallTable::MAGIC {
        let msg = b"PANIC!\0";
        unsafe { (ct.debug_print)(msg.as_ptr()) };

        if let Some(loc) = info.location() {
            // Print file/line info
            let mut buf = [0u8; 128];
            let file = loc.file().as_bytes();
            let len = file.len().min(100);
            buf[..len].copy_from_slice(&file[..len]);
            buf[len] = 0;
            unsafe { (ct.debug_print)(buf.as_ptr()) };
        }
    }
    loop { core::hint::spin_loop(); }
}
```

### Common panic causes

1. **Array index out of bounds** - Check all array accesses
2. **Integer overflow** - Use `wrapping_add`, `saturating_add` in release
3. **Unwrap on None** - Avoid `.unwrap()`, use pattern matching
4. **Division by zero** - Check denominators

---

## Debug Helpers

### Debug print helper

```rust
fn debug(msg: &str) {
    let mut buf = [0u8; 256];
    let len = msg.len().min(255);
    buf[..len].copy_from_slice(&msg.as_bytes()[..len]);
    buf[len] = 0;
    unsafe { (call_table().debug_print)(buf.as_ptr()) };
}
```

### Debug print with number

```rust
fn debug_u64(prefix: &str, value: u64) {
    let mut buf = [0u8; 64];
    let prefix_bytes = prefix.as_bytes();
    let prefix_len = prefix_bytes.len().min(32);
    buf[..prefix_len].copy_from_slice(&prefix_bytes[..prefix_len]);

    // Simple hex conversion
    let hex = b"0123456789abcdef";
    let mut pos = prefix_len;
    buf[pos] = b'0'; pos += 1;
    buf[pos] = b'x'; pos += 1;

    for i in (0..16).rev() {
        let nibble = ((value >> (i * 4)) & 0xf) as usize;
        buf[pos] = hex[nibble];
        pos += 1;
    }
    buf[pos] = 0;

    unsafe { (call_table().debug_print)(buf.as_ptr()) };
}
```

---

## Running with Verbose Output

```bash
# Run imago with verbose flag for detailed VMM output
sudo RUST_LOG=debug src/target/release/imago info image.qcow2

# Or with trace-level detail
sudo RUST_LOG=trace src/target/release/imago info image.qcow2
```

---

## Common Mistakes Checklist

- [ ] Built with `--release` (debug builds are huge)
- [ ] Using `cargo +nightly` for `build-std`
- [ ] Linker script path is correct in `.cargo/config.toml`
- [ ] `_start` function has correct signature and attributes
- [ ] Call table magic/version checked before use
- [ ] Null-terminated strings for FFI (`b"text\0"`)
- [ ] Sector numbers within device capacity
- [ ] Buffer sizes match sector size
