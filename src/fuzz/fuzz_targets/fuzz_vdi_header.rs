#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Header parsing (validates signature, version, geometry, UUIDs).
    if let Some(header) = vdi::VdiHeader::parse(data) {
        // Touch every field so the optimizer can't drop the parse, and
        // assert the invariants VdiHeader::parse must have enforced.
        assert_eq!(header.signature, vdi::VDI_SIGNATURE);
        assert_eq!(header.version, vdi::VDI_VERSION_1_1);
        assert_eq!(header.sector_size, vdi::VDI_SECTOR_SIZE);
        assert_eq!(header.block_size, vdi::VDI_BLOCK_SIZE);
        assert!(header.disk_size.is_multiple_of(512));
        assert!(header.offset_bmap.is_multiple_of(vdi::VDI_SECTOR_SIZE));
        assert!(header.offset_data.is_multiple_of(vdi::VDI_SECTOR_SIZE));
        assert!(header.blocks_in_image <= vdi::VDI_BLOCKS_IN_IMAGE_MAX);

        let geometry_bytes = header.blocks_in_image as u64 * header.block_size as u64;
        assert!(header.disk_size <= geometry_bytes);

        let _ = header.is_static();
        let _ = header.image_type;
        let _ = header.block_extra;
    }
});
