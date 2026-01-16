# Guest Protocol Crate

The `guest-protocol` crate provides structured messaging for guest-to-VMM
communication over the serial port.

## Overview

This crate uses Protocol Buffers (via `micropb`) to define a schema for
guest status messages. It is designed for:

- **no_std environments**: Works in bare-metal guests without heap allocation
- **Machine-parseable output**: VMM can extract structured status information
- **Interoperability**: Protocol Buffers schema allows future tooling

## Location

```
crates/guest-protocol/
├── Cargo.toml
├── build.rs              # micropb-gen code generation
├── proto/
│   └── guest.proto       # Protocol Buffers schema
└── src/
    └── lib.rs            # Re-exports and helpers
```

## Schema

The protocol defines several message types:

```protobuf
enum Level {
  DEBUG = 0;
  INFO = 1;
  PROGRESS = 2;
  ERROR = 3;
  COMPLETE = 4;
}

message GuestMessage {
  Level level = 1;
  oneof payload {
    InitMessage init = 2;
    CapacityMessage capacity = 3;
    ProgressMessage progress = 4;
    ErrorMessage error = 5;
    CompleteMessage complete = 6;
  }
}
```

## Message Types

| Message | Purpose | Fields |
|---------|---------|--------|
| InitMessage | Device initialization stages | stage, device, address |
| CapacityMessage | Device capacity info | device, sectors, bytes |
| ProgressMessage | Operation progress | operation, current, total, percent |
| ErrorMessage | Error details | operation, device, sector, status |
| CompleteMessage | Operation completion | operation, count, success |

## Framing

Messages are framed with a 2-byte little-endian length prefix:

```
[len_lo][len_hi][protobuf_data...]
```

This allows the VMM to parse message boundaries from the serial stream.

## Usage

### Guest Side (no_std)

```rust
use guest_protocol::{init_message, encode_framed};

let msg = init_message("probe", "input", 0x100000);
let mut buf = [0u8; 128];
if let Some(len) = encode_framed(&msg, &mut buf) {
    serial_write(&buf[..len]);
}
```

### VMM Side (std)

```rust
use guest_protocol::decode_framed;

// Read from serial buffer
if let Some((msg, consumed)) = decode_framed(&buffer) {
    match msg.payload {
        Some(Payload::Progress(p)) => {
            println!("Progress: {}/{}", p.current, p.total);
        }
        _ => {}
    }
    // Consume `consumed` bytes from buffer
}
```

## Dependencies

- `micropb`: Protocol Buffers encoding/decoding (no_std compatible)
- `heapless`: Fixed-capacity containers for string fields

## Build Requirements

The `micropb-gen` build dependency requires `protoc` (Protocol Buffers
compiler) to be installed on the system.

## Features

- `std`: Enables VMM-side decoding support (not needed for guests)

## Current Status

The crate is implemented but not yet integrated into the virtio-block
prototype. The prototype uses simple serial strings for debugging output
instead. Future prototypes may use this crate for structured messaging.
