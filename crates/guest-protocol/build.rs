//! Build script for generating Rust code from Protocol Buffers.
//!
//! Uses micropb-gen to generate no_std, no_alloc compatible code.

use std::env;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let proto_file = "proto/guest.proto";

    // Configure generator for no_std, no_alloc environment
    let mut generator = micropb_gen::Generator::new();

    // Use heapless containers for strings and bytes (fixed capacity)
    generator.use_container_heapless();

    // Configure capacities for string fields
    // Stage names like "probe", "features", "queue" are short
    // Device names like "input", "output" are short
    // Operation names like "copy", "read", "write" are short
    generator.configure(
        ".",
        micropb_gen::Config::new()
            .max_bytes(32) // Max string length for stage/device/operation names
            .max_len(17), // VmmConfig.devices: up to 16 chain inputs + 1 output
    );

    // Configure longer strings for file paths in InfoResultMessage
    // QCOW2 spec allows backing file paths up to 1023 bytes
    generator.configure(
        ".guest.InfoResultMessage.backing_file",
        micropb_gen::Config::new().max_bytes(1024),
    );
    generator.configure(
        ".guest.InfoResultMessage.external_data_file",
        micropb_gen::Config::new().max_bytes(1024),
    );

    // Configure UUID field for VDI (36 characters: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
    generator.configure(
        ".guest.VdiInfo.uuid",
        micropb_gen::Config::new().max_bytes(48),
    );

    // Configure LUKS UUID field (36 characters, same as VDI)
    generator.configure(
        ".guest.LuksInfo.uuid",
        micropb_gen::Config::new().max_bytes(48),
    );

    // Snapshot names match qemu-img's QCOW_MAX_SNAPSHOT_NAME (256
    // bytes including the nul; instar carries them without the
    // nul so 256 is the cap). Snapshot IDs are decimal strings;
    // 32 is generous.
    generator.configure(
        ".guest.SnapshotEntryMessage.name",
        micropb_gen::Config::new().max_bytes(256),
    );
    generator.configure(
        ".guest.SnapshotResultMessage.assigned_id",
        micropb_gen::Config::new().max_bytes(64),
    );

    // Generate the Rust module
    generator
        .compile_protos(&[proto_file], out_dir.join("guest.rs"))
        .expect("Failed to compile proto files");

    // Tell Cargo to rerun if the proto file changes
    println!("cargo:rerun-if-changed={}", proto_file);
}
