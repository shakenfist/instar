"""
Adversarial image tests for imago.

These tests verify that imago safely handles malicious and malformed images
without crashing, hanging, or consuming excessive resources. Each test uses
the run_adversarial() helper which enforces timeouts and memory limits.

See PLAN-adversarial-images.md for the full adversarial testing strategy.
"""

import tempfile
from pathlib import Path

from base import ImagoTestBase


class TestAdversarialCompressionBomb(ImagoTestBase):
    """Verify compression bomb images are handled safely."""


    def test_info_compression_bomb_zlib(self):
        image = self.get_adversarial_image('qcow2-compression-bomb-zlib')
        self.run_adversarial(
            [str(self.get_imago_binary()), 'info', str(image.path)],
            timeout=10
        )
        # info may succeed or fail — either is acceptable as long as
        # no crash or hang

    def test_check_compression_bomb_zlib(self):
        image = self.get_adversarial_image('qcow2-compression-bomb-zlib')
        self.run_adversarial(
            [str(self.get_imago_binary()), 'check', str(image.path)],
            timeout=30
        )

    def test_convert_compression_bomb_zlib(self):
        image = self.get_adversarial_image('qcow2-compression-bomb-zlib')
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            self.run_adversarial(
                [str(self.get_imago_binary()), 'convert',
                 str(image.path), out.name],
                timeout=30
            )
            # Output file should not be excessively large
            out_size = Path(out.name).stat().st_size
            self.assertLess(
                out_size, 100 * 1024 * 1024,
                'Output file suspiciously large for compression bomb'
            )

    def test_info_compression_bomb_zstd(self):
        image = self.get_adversarial_image('qcow2-compression-bomb-zstd')
        _ = self.run_adversarial(
            [str(self.get_imago_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_check_compression_bomb_zstd(self):
        image = self.get_adversarial_image('qcow2-compression-bomb-zstd')
        _ = self.run_adversarial(
            [str(self.get_imago_binary()), 'check', str(image.path)],
            timeout=30
        )

    def test_convert_compression_bomb_zstd(self):
        image = self.get_adversarial_image('qcow2-compression-bomb-zstd')
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            _ = self.run_adversarial(
                [str(self.get_imago_binary()), 'convert',
                 str(image.path), out.name],
                timeout=30
            )
            out_size = Path(out.name).stat().st_size
            self.assertLess(
                out_size, 100 * 1024 * 1024,
                'Output file suspiciously large for compression bomb'
            )


class TestAdversarialCircularChain(ImagoTestBase):
    """Verify circular backing chain images are detected and rejected."""


    def test_info_circular_2(self):
        image = self.get_adversarial_image('qcow2-circular-2')
        self.run_adversarial(
            [str(self.get_imago_binary()), 'info', str(image.path)],
            timeout=10
        )
        # Info on the overlay itself should work (no chain traversal)

    def test_check_chain_circular_2(self):
        image = self.get_adversarial_image('qcow2-circular-2')
        _stdout, _stderr, rc = self.run_adversarial(
            [str(self.get_imago_binary()), 'check', '--chain',
             str(image.path)],
            timeout=10
        )
        # Should reject with non-zero exit, not loop forever
        self.assertNotEqual(0, rc, 'Circular chain should be rejected')

    def test_convert_circular_2(self):
        image = self.get_adversarial_image('qcow2-circular-2')
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            _stdout, _stderr, rc = self.run_adversarial(
                [str(self.get_imago_binary()), 'convert',
                 str(image.path), out.name],
                timeout=10
            )
            self.assertNotEqual(0, rc, 'Circular chain should be rejected')

    def test_check_chain_circular_3(self):
        image = self.get_adversarial_image('qcow2-circular-3')
        _stdout, _stderr, rc = self.run_adversarial(
            [str(self.get_imago_binary()), 'check', '--chain',
             str(image.path)],
            timeout=10
        )
        self.assertNotEqual(0, rc, 'Circular chain should be rejected')

    def test_convert_circular_3(self):
        image = self.get_adversarial_image('qcow2-circular-3')
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            _stdout, _stderr, rc = self.run_adversarial(
                [str(self.get_imago_binary()), 'convert',
                 str(image.path), out.name],
                timeout=10
            )
            self.assertNotEqual(0, rc, 'Circular chain should be rejected')

    def test_check_chain_self_referencing(self):
        image = self.get_adversarial_image('qcow2-self-referencing')
        stdout, stderr, rc = self.run_adversarial(
            [str(self.get_imago_binary()), 'check', '--chain',
             str(image.path)],
            timeout=10
        )
        self.assertNotEqual(0, rc, 'Self-referencing chain should be rejected')

    def test_convert_self_referencing(self):
        image = self.get_adversarial_image('qcow2-self-referencing')
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            _stdout, _stderr, rc = self.run_adversarial(
                [str(self.get_imago_binary()), 'convert',
                 str(image.path), out.name],
                timeout=10
            )
            self.assertNotEqual(0, rc, 'Self-referencing chain should be rejected')


class TestAdversarialDeepChain(ImagoTestBase):
    """Verify deep backing chains are handled correctly at the depth limit."""


    def test_convert_chain_depth_16(self):
        """Chain at 16 levels exceeds device limit for convert.

        Convert needs an output device, so 16 input + 1 output = 17
        exceeds the 16-device maximum. This should be rejected cleanly.
        """
        image = self.get_adversarial_image('qcow2-chain-depth-16')
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            stdout, stderr, rc = self.run_adversarial(
                [str(self.get_imago_binary()), 'convert',
                 str(image.path), out.name],
                timeout=30
            )
            self.assertNotEqual(
                0, rc,
                'Chain depth 16 convert should be rejected (needs output device)'
            )

    def test_convert_chain_depth_17(self):
        """Chain at 17 levels should be rejected."""
        image = self.get_adversarial_image('qcow2-chain-depth-17')
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            stdout, stderr, rc = self.run_adversarial(
                [str(self.get_imago_binary()), 'convert',
                 str(image.path), out.name],
                timeout=10
            )
            self.assertNotEqual(
                0, rc,
                'Chain depth 17 should be rejected'
            )

    def test_check_chain_depth_16(self):
        image = self.get_adversarial_image('qcow2-chain-depth-16')
        stdout, stderr, rc = self.run_adversarial(
            [str(self.get_imago_binary()), 'check', '--chain',
             str(image.path)],
            timeout=30
        )
        self.assertEqual(
            0, rc,
            f'Chain depth 16 check should succeed: {stderr}'
        )

    def test_check_chain_depth_17(self):
        image = self.get_adversarial_image('qcow2-chain-depth-17')
        _stdout, _stderr, rc = self.run_adversarial(
            [str(self.get_imago_binary()), 'check', '--chain',
             str(image.path)],
            timeout=10
        )
        self.assertNotEqual(
            0, rc,
            'Chain depth 17 check should be rejected'
        )


class TestAdversarialIntegerOverflow(ImagoTestBase):
    """Verify integer overflow triggers in header fields are handled safely."""


    def test_info_l1_overflow(self):
        image = self.get_adversarial_image('qcow2-l1-overflow')
        _, _, _ = self.run_adversarial(
            [str(self.get_imago_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_check_l1_overflow(self):
        image = self.get_adversarial_image('qcow2-l1-overflow')
        _, _, _ = self.run_adversarial(
            [str(self.get_imago_binary()), 'check', str(image.path)],
            timeout=10
        )

    def test_info_l1_zero(self):
        image = self.get_adversarial_image('qcow2-l1-zero')
        _, _, _ = self.run_adversarial(
            [str(self.get_imago_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_check_l1_zero(self):
        image = self.get_adversarial_image('qcow2-l1-zero')
        _, _, _ = self.run_adversarial(
            [str(self.get_imago_binary()), 'check', str(image.path)],
            timeout=10
        )

    def test_info_cluster_bits_low(self):
        """Info reports header fields — no crash expected for cluster_bits=8."""
        image = self.get_adversarial_image('qcow2-cluster-bits-low')
        _, _, _ = self.run_adversarial(
            [str(self.get_imago_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_info_cluster_bits_high(self):
        """Info reports header fields — no crash expected for cluster_bits=22."""
        image = self.get_adversarial_image('qcow2-cluster-bits-high')
        _, _, _ = self.run_adversarial(
            [str(self.get_imago_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_convert_l1_overflow(self):
        image = self.get_adversarial_image('qcow2-l1-overflow')
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            _, _, _ = self.run_adversarial(
                [str(self.get_imago_binary()), 'convert',
                 str(image.path), out.name],
                timeout=10
            )

    def test_convert_cluster_bits_low(self):
        image = self.get_adversarial_image('qcow2-cluster-bits-low')
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            _, _, rc = self.run_adversarial(
                [str(self.get_imago_binary()), 'convert',
                 str(image.path), out.name],
                timeout=10
            )
            self.assertNotEqual(0, rc, 'cluster_bits=8 should be rejected')


class TestAdversarialRefcountOrder(ImagoTestBase):
    """Verify refcount_order edge cases are handled safely."""


    def test_info_refcount_order_7(self):
        image = self.get_adversarial_image('qcow2-refcount-order-7')
        self.run_adversarial(
            [str(self.get_imago_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_check_refcount_order_7(self):
        image = self.get_adversarial_image('qcow2-refcount-order-7')
        self.run_adversarial(
            [str(self.get_imago_binary()), 'check', str(image.path)],
            timeout=10
        )

    def test_info_refcount_order_255(self):
        image = self.get_adversarial_image('qcow2-refcount-order-255')
        self.run_adversarial(
            [str(self.get_imago_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_check_refcount_order_255(self):
        image = self.get_adversarial_image('qcow2-refcount-order-255')
        self.run_adversarial(
            [str(self.get_imago_binary()), 'check', str(image.path)],
            timeout=10
        )


class TestAdversarialOversizedVsize(ImagoTestBase):
    """Verify oversized virtual size values are handled safely."""


    def test_info_vsize_petabyte(self):
        """Info should report the petabyte size without crashing."""
        image = self.get_adversarial_image('qcow2-vsize-petabyte')
        self.run_adversarial(
            [str(self.get_imago_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_check_vsize_petabyte(self):
        image = self.get_adversarial_image('qcow2-vsize-petabyte')
        self.run_adversarial(
            [str(self.get_imago_binary()), 'check', str(image.path)],
            timeout=30
        )

    # NOTE: convert with petabyte vsize is intentionally not tested here.
    # Imago iterates the full virtual address space during conversion,
    # so a 1PB vsize would take unreasonably long. This is a known
    # resource exhaustion vector via oversized virtual size — tracked
    # as a potential future improvement (early termination when all
    # L1 entries are unallocated).

    def test_info_vsize_max(self):
        image = self.get_adversarial_image('qcow2-vsize-max')
        self.run_adversarial(
            [str(self.get_imago_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_check_vsize_max(self):
        image = self.get_adversarial_image('qcow2-vsize-max')
        self.run_adversarial(
            [str(self.get_imago_binary()), 'check', str(image.path)],
            timeout=30
        )


class TestAdversarialVmdkGrainSize(ImagoTestBase):
    """Verify VMDK grain size boundary values are handled safely."""


    def test_info_grain_size_zero(self):
        image = self.get_adversarial_image('vmdk-grain-size-zero')
        self.run_adversarial(
            [str(self.get_imago_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_check_grain_size_zero(self):
        image = self.get_adversarial_image('vmdk-grain-size-zero')
        self.run_adversarial(
            [str(self.get_imago_binary()), 'check', str(image.path)],
            timeout=10
        )

    def test_info_grain_size_huge(self):
        image = self.get_adversarial_image('vmdk-grain-size-huge')
        self.run_adversarial(
            [str(self.get_imago_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_check_grain_size_huge(self):
        image = self.get_adversarial_image('vmdk-grain-size-huge')
        self.run_adversarial(
            [str(self.get_imago_binary()), 'check', str(image.path)],
            timeout=10
        )


class TestAdversarialVhdxConflictingHeaders(ImagoTestBase):
    """Verify VHDX with conflicting dual headers is handled correctly."""


    def test_info_conflicting_headers(self):
        image = self.get_adversarial_image('vhdx-conflicting-headers')
        self.run_adversarial(
            [str(self.get_imago_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_check_conflicting_headers(self):
        image = self.get_adversarial_image('vhdx-conflicting-headers')
        self.run_adversarial(
            [str(self.get_imago_binary()), 'check', str(image.path)],
            timeout=10
        )


class TestAdversarialBatBeyondEof(ImagoTestBase):
    """Verify BAT entries beyond EOF are handled safely."""


    def test_info_vhd_bat_beyond_eof(self):
        image = self.get_adversarial_image('vhd-bat-beyond-eof')
        _ = self.run_adversarial(
            [str(self.get_imago_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_check_vhd_bat_beyond_eof(self):
        image = self.get_adversarial_image('vhd-bat-beyond-eof')
        _ = self.run_adversarial(
            [str(self.get_imago_binary()), 'check', str(image.path)],
            timeout=10
        )

    def test_convert_vhd_bat_beyond_eof(self):
        image = self.get_adversarial_image('vhd-bat-beyond-eof')
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            self.run_adversarial(
                [str(self.get_imago_binary()), 'convert',
                 str(image.path), out.name],
                timeout=10
            )

    def test_info_vhdx_bat_beyond_eof(self):
        image = self.get_adversarial_image('vhdx-bat-beyond-eof')
        self.run_adversarial(
            [str(self.get_imago_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_check_vhdx_bat_beyond_eof(self):
        image = self.get_adversarial_image('vhdx-bat-beyond-eof')
        _ = self.run_adversarial(
            [str(self.get_imago_binary()), 'check', str(image.path)],
            timeout=10
        )

    def test_convert_vhdx_bat_beyond_eof(self):
        image = self.get_adversarial_image('vhdx-bat-beyond-eof')
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            self.run_adversarial(
                [str(self.get_imago_binary()), 'convert',
                 str(image.path), out.name],
                timeout=10
            )


class TestAdversarialPolyglot(ImagoTestBase):
    """Verify polyglot files are handled safely.

    These files have valid magic bytes for one format but body content
    from another format. Format detection should work (magic wins),
    but structural validation should catch the inconsistency.
    """


    def test_info_polyglot_qcow2_vmdk(self):
        """QCOW2 magic with VMDK descriptor body — info should detect as QCOW2."""
        image = self.get_adversarial_image('polyglot-qcow2-vmdk')
        self.run_adversarial(
            [str(self.get_imago_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_check_polyglot_qcow2_vmdk(self):
        image = self.get_adversarial_image('polyglot-qcow2-vmdk')
        _ = self.run_adversarial(
            [str(self.get_imago_binary()), 'check', str(image.path)],
            timeout=10
        )

    def test_convert_polyglot_qcow2_vmdk(self):
        image = self.get_adversarial_image('polyglot-qcow2-vmdk')
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            _, stderr, rc = self.run_adversarial(
                [str(self.get_imago_binary()), 'convert',
                 str(image.path), out.name],
                timeout=10
            )

    def test_info_polyglot_qcow2_elf(self):
        """QCOW2 magic with ELF binary body — info should detect as QCOW2."""
        image = self.get_adversarial_image('polyglot-qcow2-elf')
        _ = self.run_adversarial(
            [str(self.get_imago_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_check_polyglot_qcow2_elf(self):
        image = self.get_adversarial_image('polyglot-qcow2-elf')
        _, _, _ = self.run_adversarial(
            [str(self.get_imago_binary()), 'check', str(image.path)],
            timeout=10
        )

    def test_convert_polyglot_qcow2_elf(self):
        image = self.get_adversarial_image('polyglot-qcow2-elf')
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            _ = self.run_adversarial(
                [str(self.get_imago_binary()), 'convert',
                 str(image.path), out.name],
                timeout=10
            )


class TestAdversarialTruncatedHeader(ImagoTestBase):
    """Verify truncated format headers fail gracefully.

    These files have valid magic bytes but are truncated mid-field,
    so the parser cannot read the complete header. All operations
    should fail with a clear error, not crash.
    """


    def test_info_truncated_qcow2(self):
        image = self.get_adversarial_image('qcow2-truncated-header-v2')
        _ = self.run_adversarial(
            [str(self.get_imago_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_check_truncated_qcow2(self):
        image = self.get_adversarial_image('qcow2-truncated-header-v2')
        _ = self.run_adversarial(
            [str(self.get_imago_binary()), 'check', str(image.path)],
            timeout=10
        )

    def test_convert_truncated_qcow2(self):
        image = self.get_adversarial_image('qcow2-truncated-header-v2')
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            self.run_adversarial(
                [str(self.get_imago_binary()), 'convert',
                 str(image.path), out.name],
                timeout=10
            )

    def test_info_truncated_vmdk(self):
        image = self.get_adversarial_image('vmdk-truncated-after-magic')
        self.run_adversarial(
            [str(self.get_imago_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_check_truncated_vmdk(self):
        image = self.get_adversarial_image('vmdk-truncated-after-magic')
        self.run_adversarial(
            [str(self.get_imago_binary()), 'check', str(image.path)],
            timeout=10
        )

    def test_convert_truncated_vmdk(self):
        image = self.get_adversarial_image('vmdk-truncated-after-magic')
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            self.run_adversarial(
                [str(self.get_imago_binary()), 'convert',
                 str(image.path), out.name],
                timeout=10
            )

    def test_info_truncated_vhd(self):
        image = self.get_adversarial_image('vhd-truncated-footer')
        self.run_adversarial(
            [str(self.get_imago_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_check_truncated_vhd(self):
        image = self.get_adversarial_image('vhd-truncated-footer')
        self.run_adversarial(
            [str(self.get_imago_binary()), 'check', str(image.path)],
            timeout=10
        )

    def test_convert_truncated_vhd(self):
        image = self.get_adversarial_image('vhd-truncated-footer')
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            self.run_adversarial(
                [str(self.get_imago_binary()), 'convert',
                 str(image.path), out.name],
                timeout=10
            )


class TestAdversarialVmdkDescriptor(ImagoTestBase):
    """Verify VMDK descriptor attacks are handled safely.

    These test the VMDK descriptor parser with adversarial input:
    null bytes, multiple extent declarations, and inflated size claims.
    """


    def test_info_descriptor_null_bytes(self):
        image = self.get_adversarial_image('vmdk-descriptor-null-bytes')
        self.run_adversarial(
            [str(self.get_imago_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_check_descriptor_null_bytes(self):
        image = self.get_adversarial_image('vmdk-descriptor-null-bytes')
        self.run_adversarial(
            [str(self.get_imago_binary()), 'check', str(image.path)],
            timeout=10
        )

    def test_info_descriptor_multi_extent(self):
        image = self.get_adversarial_image('vmdk-descriptor-multi-extent')
        self.run_adversarial(
            [str(self.get_imago_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_check_descriptor_multi_extent(self):
        """Check handles multi-extent VMDK without crash.

        The check operation may return rc=0 with 'does not support checks'
        if the VMDK subtype is not recognized, or reject with non-zero rc
        if multi-extent detection fires. Either is acceptable.
        """
        image = self.get_adversarial_image('vmdk-descriptor-multi-extent')
        self.run_adversarial(
            [str(self.get_imago_binary()), 'check', str(image.path)],
            timeout=10
        )

    def test_info_descriptor_huge(self):
        image = self.get_adversarial_image('vmdk-descriptor-huge')
        self.run_adversarial(
            [str(self.get_imago_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_check_descriptor_huge(self):
        image = self.get_adversarial_image('vmdk-descriptor-huge')
        self.run_adversarial(
            [str(self.get_imago_binary()), 'check', str(image.path)],
            timeout=10
        )
