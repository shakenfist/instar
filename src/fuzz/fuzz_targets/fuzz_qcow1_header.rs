#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Header parsing (validates magic, version, cluster_bits, l2_bits,
    // size, the "Image too large" L1-size bound, crypt_method,
    // backing_file_size). l1_table_offset is deliberately NOT validated by
    // the crate (qemu tolerates 0 / unaligned / past-EOF at open) so no
    // invariant is asserted on it here.
    if let Some(header) = qcow1::Qcow1Header::parse(data) {
        // Touch every field so the optimizer can't drop the parse, and
        // assert the invariants Qcow1Header::parse must have enforced.
        assert_eq!(header.cluster_size, 1u64 << header.cluster_bits);
        assert!((512..=65536).contains(&header.cluster_size));
        assert!(qcow1::QCOW1_CLUSTER_BITS_MIN <= header.cluster_bits);
        assert!(header.cluster_bits <= qcow1::QCOW1_CLUSTER_BITS_MAX);

        assert_eq!(header.l2_size, 1u64 << header.l2_bits);
        assert!((64..=8192).contains(&header.l2_size));
        assert!(qcow1::QCOW1_L2_BITS_MIN <= header.l2_bits);
        assert!(header.l2_bits <= qcow1::QCOW1_L2_BITS_MAX);

        assert!(header.l1_size <= qcow1::QCOW1_L1_SIZE_MAX);

        assert!(header.virtual_size >= 2);

        assert!(header.crypt_method <= qcow1::QCOW1_CRYPT_AES);

        assert!(header.backing_file_size <= qcow1::QCOW1_BACKING_FILE_SIZE_MAX);

        let _ = header.l1_table_offset;
        let _ = header.backing_file_offset;
        let _ = header.is_encrypted();
    }
});
