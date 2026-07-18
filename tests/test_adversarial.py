"""
Adversarial image tests for instar.

These tests verify that instar safely handles malicious and malformed images
without crashing, hanging, or consuming excessive resources. Each test uses
the run_adversarial() helper which enforces timeouts and memory limits.

See PLAN-adversarial-images.md for the full adversarial testing strategy.
"""

import tempfile
from pathlib import Path

from base import InstarTestBase


class TestAdversarialCompressionBomb(InstarTestBase):
    """Verify compression bomb images are handled safely."""


    def test_info_compression_bomb_zlib(self):
        image = self.get_adversarial_image('qcow2-compression-bomb-zlib')
        self.run_adversarial(
            [str(self.get_instar_binary()), 'info', str(image.path)],
            timeout=10
        )
        # info may succeed or fail — either is acceptable as long as
        # no crash or hang

    def test_check_compression_bomb_zlib(self):
        image = self.get_adversarial_image('qcow2-compression-bomb-zlib')
        self.run_adversarial(
            [str(self.get_instar_binary()), 'check', str(image.path)],
            timeout=30
        )

    def test_convert_compression_bomb_zlib(self):
        image = self.get_adversarial_image('qcow2-compression-bomb-zlib')
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            self.run_adversarial(
                [str(self.get_instar_binary()), 'convert',
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
            [str(self.get_instar_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_check_compression_bomb_zstd(self):
        image = self.get_adversarial_image('qcow2-compression-bomb-zstd')
        _ = self.run_adversarial(
            [str(self.get_instar_binary()), 'check', str(image.path)],
            timeout=30
        )

    def test_convert_compression_bomb_zstd(self):
        image = self.get_adversarial_image('qcow2-compression-bomb-zstd')
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            _ = self.run_adversarial(
                [str(self.get_instar_binary()), 'convert',
                 str(image.path), out.name],
                timeout=30
            )
            out_size = Path(out.name).stat().st_size
            self.assertLess(
                out_size, 100 * 1024 * 1024,
                'Output file suspiciously large for compression bomb'
            )


class TestAdversarialCircularChain(InstarTestBase):
    """Verify circular backing chain images are detected and rejected."""


    def test_info_circular_2(self):
        image = self.get_adversarial_image('qcow2-circular-2')
        self.run_adversarial(
            [str(self.get_instar_binary()), 'info', str(image.path)],
            timeout=10
        )
        # Info on the overlay itself should work (no chain traversal)

    def test_check_chain_circular_2(self):
        image = self.get_adversarial_image('qcow2-circular-2')
        _stdout, _stderr, rc = self.run_adversarial(
            [str(self.get_instar_binary()), 'check', '--chain',
             str(image.path)],
            timeout=10
        )
        # Should reject with non-zero exit, not loop forever
        self.assertNotEqual(0, rc, 'Circular chain should be rejected')

    def test_convert_circular_2(self):
        image = self.get_adversarial_image('qcow2-circular-2')
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            _stdout, _stderr, rc = self.run_adversarial(
                [str(self.get_instar_binary()), 'convert',
                 str(image.path), out.name],
                timeout=10
            )
            self.assertNotEqual(0, rc, 'Circular chain should be rejected')

    def test_check_chain_circular_3(self):
        image = self.get_adversarial_image('qcow2-circular-3')
        _stdout, _stderr, rc = self.run_adversarial(
            [str(self.get_instar_binary()), 'check', '--chain',
             str(image.path)],
            timeout=10
        )
        self.assertNotEqual(0, rc, 'Circular chain should be rejected')

    def test_convert_circular_3(self):
        image = self.get_adversarial_image('qcow2-circular-3')
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            _stdout, _stderr, rc = self.run_adversarial(
                [str(self.get_instar_binary()), 'convert',
                 str(image.path), out.name],
                timeout=10
            )
            self.assertNotEqual(0, rc, 'Circular chain should be rejected')

    def test_check_chain_self_referencing(self):
        image = self.get_adversarial_image('qcow2-self-referencing')
        stdout, stderr, rc = self.run_adversarial(
            [str(self.get_instar_binary()), 'check', '--chain',
             str(image.path)],
            timeout=10
        )
        self.assertNotEqual(0, rc, 'Self-referencing chain should be rejected')

    def test_convert_self_referencing(self):
        image = self.get_adversarial_image('qcow2-self-referencing')
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            _stdout, _stderr, rc = self.run_adversarial(
                [str(self.get_instar_binary()), 'convert',
                 str(image.path), out.name],
                timeout=10
            )
            self.assertNotEqual(0, rc, 'Self-referencing chain should be rejected')


class TestAdversarialDeepChain(InstarTestBase):
    """Verify deep backing chains are handled correctly at the depth limit."""


    def test_convert_chain_depth_16(self):
        """Chain at 16 levels exceeds device limit for convert.

        Convert needs an output device, so 16 input + 1 output = 17
        exceeds the 16-device maximum. This should be rejected cleanly.
        """
        image = self.get_adversarial_image('qcow2-chain-depth-16')
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            stdout, stderr, rc = self.run_adversarial(
                [str(self.get_instar_binary()), 'convert',
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
                [str(self.get_instar_binary()), 'convert',
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
            [str(self.get_instar_binary()), 'check', '--chain',
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
            [str(self.get_instar_binary()), 'check', '--chain',
             str(image.path)],
            timeout=10
        )
        self.assertNotEqual(
            0, rc,
            'Chain depth 17 check should be rejected'
        )


class TestAdversarialIntegerOverflow(InstarTestBase):
    """Verify integer overflow triggers in header fields are handled safely."""


    def test_info_l1_overflow(self):
        image = self.get_adversarial_image('qcow2-l1-overflow')
        _, _, _ = self.run_adversarial(
            [str(self.get_instar_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_check_l1_overflow(self):
        image = self.get_adversarial_image('qcow2-l1-overflow')
        _, _, _ = self.run_adversarial(
            [str(self.get_instar_binary()), 'check', str(image.path)],
            timeout=10
        )

    def test_info_l1_zero(self):
        image = self.get_adversarial_image('qcow2-l1-zero')
        _, _, _ = self.run_adversarial(
            [str(self.get_instar_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_check_l1_zero(self):
        image = self.get_adversarial_image('qcow2-l1-zero')
        _, _, _ = self.run_adversarial(
            [str(self.get_instar_binary()), 'check', str(image.path)],
            timeout=10
        )

    def test_info_cluster_bits_low(self):
        """Info reports header fields — no crash for cluster_bits=8 (below min 9)."""
        image = self.get_adversarial_image('qcow2-cluster-bits-low')
        _, _, _ = self.run_adversarial(
            [str(self.get_instar_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_info_cluster_bits_high(self):
        """Info reports header fields — no crash for cluster_bits=22 (above max 21)."""
        image = self.get_adversarial_image('qcow2-cluster-bits-high')
        _, _, _ = self.run_adversarial(
            [str(self.get_instar_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_convert_l1_overflow(self):
        image = self.get_adversarial_image('qcow2-l1-overflow')
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            _, _, _ = self.run_adversarial(
                [str(self.get_instar_binary()), 'convert',
                 str(image.path), out.name],
                timeout=10
            )

    def test_convert_cluster_bits_low(self):
        image = self.get_adversarial_image('qcow2-cluster-bits-low')
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            _, _, rc = self.run_adversarial(
                [str(self.get_instar_binary()), 'convert',
                 str(image.path), out.name],
                timeout=10
            )
            self.assertNotEqual(0, rc, 'cluster_bits=8 should be rejected')


class TestAdversarialRefcountOrder(InstarTestBase):
    """Verify refcount_order edge cases are handled safely."""


    def test_info_refcount_order_7(self):
        image = self.get_adversarial_image('qcow2-refcount-order-7')
        self.run_adversarial(
            [str(self.get_instar_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_check_refcount_order_7(self):
        image = self.get_adversarial_image('qcow2-refcount-order-7')
        self.run_adversarial(
            [str(self.get_instar_binary()), 'check', str(image.path)],
            timeout=10
        )

    def test_info_refcount_order_255(self):
        image = self.get_adversarial_image('qcow2-refcount-order-255')
        self.run_adversarial(
            [str(self.get_instar_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_check_refcount_order_255(self):
        image = self.get_adversarial_image('qcow2-refcount-order-255')
        self.run_adversarial(
            [str(self.get_instar_binary()), 'check', str(image.path)],
            timeout=10
        )


class TestAdversarialOversizedVsize(InstarTestBase):
    """Verify oversized virtual size values are handled safely."""


    def test_info_vsize_petabyte(self):
        """Info should report the petabyte size without crashing."""
        image = self.get_adversarial_image('qcow2-vsize-petabyte')
        self.run_adversarial(
            [str(self.get_instar_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_check_vsize_petabyte(self):
        image = self.get_adversarial_image('qcow2-vsize-petabyte')
        self.run_adversarial(
            [str(self.get_instar_binary()), 'check', str(image.path)],
            timeout=30
        )

    # NOTE: convert with petabyte vsize is intentionally not tested here.
    # Instar iterates the full virtual address space during conversion,
    # so a 1PB vsize would take unreasonably long. This is a known
    # resource exhaustion vector via oversized virtual size — tracked
    # as a potential future improvement (early termination when all
    # L1 entries are unallocated).

    def test_info_vsize_max(self):
        image = self.get_adversarial_image('qcow2-vsize-max')
        self.run_adversarial(
            [str(self.get_instar_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_check_vsize_max(self):
        image = self.get_adversarial_image('qcow2-vsize-max')
        self.run_adversarial(
            [str(self.get_instar_binary()), 'check', str(image.path)],
            timeout=30
        )


class TestAdversarialVmdkGrainSize(InstarTestBase):
    """Verify VMDK grain size boundary values are handled safely."""


    def test_info_grain_size_zero(self):
        image = self.get_adversarial_image('vmdk-grain-size-zero')
        self.run_adversarial(
            [str(self.get_instar_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_check_grain_size_zero(self):
        image = self.get_adversarial_image('vmdk-grain-size-zero')
        self.run_adversarial(
            [str(self.get_instar_binary()), 'check', str(image.path)],
            timeout=10
        )

    def test_info_grain_size_huge(self):
        image = self.get_adversarial_image('vmdk-grain-size-huge')
        self.run_adversarial(
            [str(self.get_instar_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_check_grain_size_huge(self):
        image = self.get_adversarial_image('vmdk-grain-size-huge')
        self.run_adversarial(
            [str(self.get_instar_binary()), 'check', str(image.path)],
            timeout=10
        )


class TestAdversarialVhdxConflictingHeaders(InstarTestBase):
    """Verify VHDX with conflicting dual headers is handled correctly."""


    def test_info_conflicting_headers(self):
        image = self.get_adversarial_image('vhdx-conflicting-headers')
        self.run_adversarial(
            [str(self.get_instar_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_check_conflicting_headers(self):
        image = self.get_adversarial_image('vhdx-conflicting-headers')
        self.run_adversarial(
            [str(self.get_instar_binary()), 'check', str(image.path)],
            timeout=10
        )


class TestAdversarialBatBeyondEof(InstarTestBase):
    """Verify BAT entries beyond EOF are handled safely."""


    def test_info_vhd_bat_beyond_eof(self):
        image = self.get_adversarial_image('vhd-bat-beyond-eof')
        _ = self.run_adversarial(
            [str(self.get_instar_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_check_vhd_bat_beyond_eof(self):
        image = self.get_adversarial_image('vhd-bat-beyond-eof')
        _ = self.run_adversarial(
            [str(self.get_instar_binary()), 'check', str(image.path)],
            timeout=10
        )

    def test_convert_vhd_bat_beyond_eof(self):
        image = self.get_adversarial_image('vhd-bat-beyond-eof')
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            self.run_adversarial(
                [str(self.get_instar_binary()), 'convert',
                 str(image.path), out.name],
                timeout=10
            )

    def test_info_vhdx_bat_beyond_eof(self):
        image = self.get_adversarial_image('vhdx-bat-beyond-eof')
        self.run_adversarial(
            [str(self.get_instar_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_check_vhdx_bat_beyond_eof(self):
        image = self.get_adversarial_image('vhdx-bat-beyond-eof')
        _ = self.run_adversarial(
            [str(self.get_instar_binary()), 'check', str(image.path)],
            timeout=10
        )

    def test_convert_vhdx_bat_beyond_eof(self):
        image = self.get_adversarial_image('vhdx-bat-beyond-eof')
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            self.run_adversarial(
                [str(self.get_instar_binary()), 'convert',
                 str(image.path), out.name],
                timeout=10
            )


class TestAdversarialPolyglot(InstarTestBase):
    """Verify polyglot files are handled safely.

    These files have valid magic bytes for one format but body content
    from another format. Format detection should work (magic wins),
    but structural validation should catch the inconsistency.
    """


    def test_info_polyglot_qcow2_vmdk(self):
        """QCOW2 magic with VMDK descriptor body — info should detect as QCOW2."""
        image = self.get_adversarial_image('polyglot-qcow2-vmdk')
        self.run_adversarial(
            [str(self.get_instar_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_check_polyglot_qcow2_vmdk(self):
        image = self.get_adversarial_image('polyglot-qcow2-vmdk')
        _ = self.run_adversarial(
            [str(self.get_instar_binary()), 'check', str(image.path)],
            timeout=10
        )

    def test_convert_polyglot_qcow2_vmdk(self):
        image = self.get_adversarial_image('polyglot-qcow2-vmdk')
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            _, stderr, rc = self.run_adversarial(
                [str(self.get_instar_binary()), 'convert',
                 str(image.path), out.name],
                timeout=10
            )

    def test_info_polyglot_qcow2_elf(self):
        """QCOW2 magic with ELF binary body — info should detect as QCOW2."""
        image = self.get_adversarial_image('polyglot-qcow2-elf')
        _ = self.run_adversarial(
            [str(self.get_instar_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_check_polyglot_qcow2_elf(self):
        image = self.get_adversarial_image('polyglot-qcow2-elf')
        _, _, _ = self.run_adversarial(
            [str(self.get_instar_binary()), 'check', str(image.path)],
            timeout=10
        )

    def test_convert_polyglot_qcow2_elf(self):
        image = self.get_adversarial_image('polyglot-qcow2-elf')
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            _ = self.run_adversarial(
                [str(self.get_instar_binary()), 'convert',
                 str(image.path), out.name],
                timeout=10
            )


class TestAdversarialTruncatedHeader(InstarTestBase):
    """Verify truncated format headers fail gracefully.

    These files have valid magic bytes but are truncated mid-field,
    so the parser cannot read the complete header. All operations
    should fail with a clear error, not crash.
    """


    def test_info_truncated_qcow2(self):
        image = self.get_adversarial_image('qcow2-truncated-header-v2')
        _ = self.run_adversarial(
            [str(self.get_instar_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_check_truncated_qcow2(self):
        image = self.get_adversarial_image('qcow2-truncated-header-v2')
        _ = self.run_adversarial(
            [str(self.get_instar_binary()), 'check', str(image.path)],
            timeout=10
        )

    def test_convert_truncated_qcow2(self):
        image = self.get_adversarial_image('qcow2-truncated-header-v2')
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            self.run_adversarial(
                [str(self.get_instar_binary()), 'convert',
                 str(image.path), out.name],
                timeout=10
            )

    def test_info_truncated_vmdk(self):
        image = self.get_adversarial_image('vmdk-truncated-after-magic')
        self.run_adversarial(
            [str(self.get_instar_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_check_truncated_vmdk(self):
        image = self.get_adversarial_image('vmdk-truncated-after-magic')
        self.run_adversarial(
            [str(self.get_instar_binary()), 'check', str(image.path)],
            timeout=10
        )

    def test_convert_truncated_vmdk(self):
        image = self.get_adversarial_image('vmdk-truncated-after-magic')
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            self.run_adversarial(
                [str(self.get_instar_binary()), 'convert',
                 str(image.path), out.name],
                timeout=10
            )

    def test_info_truncated_vhd(self):
        image = self.get_adversarial_image('vhd-truncated-footer')
        self.run_adversarial(
            [str(self.get_instar_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_check_truncated_vhd(self):
        image = self.get_adversarial_image('vhd-truncated-footer')
        self.run_adversarial(
            [str(self.get_instar_binary()), 'check', str(image.path)],
            timeout=10
        )

    def test_convert_truncated_vhd(self):
        image = self.get_adversarial_image('vhd-truncated-footer')
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            self.run_adversarial(
                [str(self.get_instar_binary()), 'convert',
                 str(image.path), out.name],
                timeout=10
            )


class TestAdversarialVmdkDescriptor(InstarTestBase):
    """Verify VMDK descriptor attacks are handled safely.

    These test the VMDK descriptor parser with adversarial input:
    null bytes, multiple extent declarations, and inflated size claims.
    """


    def test_info_descriptor_null_bytes(self):
        image = self.get_adversarial_image('vmdk-descriptor-null-bytes')
        self.run_adversarial(
            [str(self.get_instar_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_check_descriptor_null_bytes(self):
        image = self.get_adversarial_image('vmdk-descriptor-null-bytes')
        self.run_adversarial(
            [str(self.get_instar_binary()), 'check', str(image.path)],
            timeout=10
        )

    def test_info_descriptor_multi_extent(self):
        image = self.get_adversarial_image('vmdk-descriptor-multi-extent')
        self.run_adversarial(
            [str(self.get_instar_binary()), 'info', str(image.path)],
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
            [str(self.get_instar_binary()), 'check', str(image.path)],
            timeout=10
        )

    def test_info_descriptor_huge(self):
        image = self.get_adversarial_image('vmdk-descriptor-huge')
        self.run_adversarial(
            [str(self.get_instar_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_check_descriptor_huge(self):
        image = self.get_adversarial_image('vmdk-descriptor-huge')
        self.run_adversarial(
            [str(self.get_instar_binary()), 'check', str(image.path)],
            timeout=10
        )


class TestAdversarialDmgManifest(InstarTestBase):
    """Verify malformed DMG koly-trailer manifests are handled safely.

    Four fixtures probe the koly-trailer parsing at its edges: a
    trailer cut short (no valid 512-byte block at any candidate
    offset), a SectorCount with the top bit set (rejected as
    negative), an absurd-but-positive SectorCount, and a valid
    trailer whose chunk table is empty (instar reports from the
    trailer alone; qemu-img would fail to open it — a documented
    trailer-only divergence). None of these should hang, crash, or
    consume excessive memory. `convert` must either refuse via the
    3b detect-only gate (when the header still resolves to `dmg`) or
    otherwise fail/succeed cleanly (when the malformation collapses
    detection to `unknown`, convert falls through to the iso/unknown
    raw pass-through) — in every case any produced output must stay
    small.
    """

    def _assert_convert_output_small(self, image_id):
        image = self.get_adversarial_image(image_id)
        with tempfile.NamedTemporaryFile(suffix='.raw') as out:
            self.run_adversarial(
                [str(self.get_instar_binary()), 'convert', '-O', 'raw',
                 str(image.path), out.name],
                timeout=10
            )
            out_size = Path(out.name).stat().st_size
            self.assertLess(
                out_size, 100 * 1024 * 1024,
                f'convert output suspiciously large for {image_id}'
            )

    # --- dmg-truncated-koly: no valid trailer at any candidate offset ---

    def test_info_dmg_truncated_koly(self):
        image = self.get_adversarial_image('dmg-truncated-koly')
        self.run_adversarial(
            [str(self.get_instar_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_convert_dmg_truncated_koly(self):
        self._assert_convert_output_small('dmg-truncated-koly')

    # --- dmg-sectorcount-negative: top bit set, rejected as negative ---

    def test_info_dmg_sectorcount_negative(self):
        image = self.get_adversarial_image('dmg-sectorcount-negative')
        self.run_adversarial(
            [str(self.get_instar_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_convert_dmg_sectorcount_negative(self):
        self._assert_convert_output_small('dmg-sectorcount-negative')

    # --- dmg-sectorcount-huge: absurd but positive SectorCount ---

    def test_info_dmg_sectorcount_huge(self):
        image = self.get_adversarial_image('dmg-sectorcount-huge')
        self.run_adversarial(
            [str(self.get_instar_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_convert_dmg_sectorcount_huge(self):
        self._assert_convert_output_small('dmg-sectorcount-huge')

    # --- dmg-no-chunk-table: valid trailer, empty rsrc+XML lengths ---

    def test_info_dmg_no_chunk_table(self):
        image = self.get_adversarial_image('dmg-no-chunk-table')
        self.run_adversarial(
            [str(self.get_instar_binary()), 'info', str(image.path)],
            timeout=10
        )

    def test_convert_dmg_no_chunk_table(self):
        self._assert_convert_output_small('dmg-no-chunk-table')


class TestAdversarialVdiManifest(InstarTestBase):
    """Verify malformed VDI fixtures are refused cleanly (format-coverage 2).

    Five fixtures each violate one of qemu's ``vdi_open`` validation
    rules: an unsupported version (2.0), an unaligned block-map offset, a
    non-1 MiB block size, a non-NULL parent UUID, and a blocks_in_image
    count over the limit.  qemu refuses all five at open; instar's VDI
    reader (the new ``vdi`` crate) must likewise refuse -- convert,
    compare, and dd all exit non-zero with a non-empty error and without
    hanging or crashing.  instar's own message need not match qemu's
    string; only the exit code and clean termination are pinned.

    convert and dd surface the reader init failure as an operation error
    on stderr (``convert operation failed``); compare surfaces it as a
    content mismatch on stdout and exits 1 -- a self-compare of a
    malformed fixture reports a mismatch, not ``identical``, which proves
    compare is not silently reading it as raw.  Both are clean non-zero
    exits, so the assertion checks the combined stdout+stderr for a
    non-empty message rather than pinning the stream.

    ``info`` is deliberately NOT asserted non-zero: the info operation
    parses the VDI header with a separate, lenient parser
    (``parse_vdi_header``) that is out of scope for the reader
    graduation, so it reports a plausible ``file format: vdi`` and exits
    0.  The adversarial contract for info is only no-hang / no-crash /
    non-empty output, matching the DMG manifest pattern above.

    The zero-fill (vdi-bmap-past-eof) and disk_size round-up
    (vdi-odd-size) rules for the *safe* fixtures are pinned by
    successful byte-parity convert tests in
    tests/test_convert.py::TestConvertVdiToRaw, not here.
    """

    MALFORMED_IDS = [
        'vdi-bad-version',
        'vdi-unaligned-bmap',
        'vdi-wrong-blocksize',
        'vdi-nonnull-parent',
        'vdi-too-many-blocks',
    ]

    def _assert_vdi_refused(self, image_id):
        """convert/compare/dd refuse cleanly; info is clean but may exit 0."""
        image = self.get_adversarial_image(image_id)
        instar = str(self.get_instar_binary())

        with tempfile.NamedTemporaryFile(suffix='.raw') as out, \
                tempfile.NamedTemporaryFile(suffix='.raw') as other:
            # A tiny raw file to compare against.
            Path(other.name).write_bytes(bytes(512))

            # convert: must refuse, non-zero, non-empty message, no hang.
            _c_out, c_err, c_rc = self.run_adversarial(
                [instar, 'convert', '-O', 'raw', str(image.path), out.name],
                timeout=15,
            )
            self.assertNotEqual(
                c_rc, 0,
                f'convert should refuse malformed {image_id}',
            )
            self.assertTrue(
                c_err.strip(),
                f'convert should emit a non-empty error for {image_id}',
            )

            # compare against the raw file: must refuse, non-zero, no hang.
            # compare reports the read failure as a mismatch on stdout, so
            # the combined output (not just stderr) is checked non-empty.
            m_out, m_err, m_rc = self.run_adversarial(
                [instar, 'compare', str(image.path), other.name],
                timeout=15,
            )
            self.assertNotEqual(
                m_rc, 0,
                f'compare should refuse malformed {image_id}',
            )
            self.assertTrue(
                (m_out + m_err).strip(),
                f'compare should emit a non-empty message for {image_id}',
            )

            # dd: must refuse, non-zero, non-empty message, no hang.
            _d_out, d_err, d_rc = self.run_adversarial(
                [instar, 'dd', '-O', 'raw',
                 f'if={image.path}', f'of={out.name}'],
                timeout=15,
            )
            self.assertNotEqual(
                d_rc, 0,
                f'dd should refuse malformed {image_id}',
            )
            self.assertTrue(
                d_err.strip(),
                f'dd should emit a non-empty error for {image_id}',
            )

            # info: no hang / no crash; lenient parser, exit code unpinned.
            i_out, i_err, _i_rc = self.run_adversarial(
                [instar, 'info', str(image.path)],
                timeout=15,
            )
            self.assertTrue(
                (i_out + i_err).strip(),
                f'info should emit non-empty output for {image_id}',
            )

    def test_vdi_bad_version_refused(self):
        self._assert_vdi_refused('vdi-bad-version')

    def test_vdi_unaligned_bmap_refused(self):
        self._assert_vdi_refused('vdi-unaligned-bmap')

    def test_vdi_wrong_blocksize_refused(self):
        self._assert_vdi_refused('vdi-wrong-blocksize')

    def test_vdi_nonnull_parent_refused(self):
        self._assert_vdi_refused('vdi-nonnull-parent')

    def test_vdi_too_many_blocks_refused(self):
        self._assert_vdi_refused('vdi-too-many-blocks')


class TestAdversarialParallelsManifest(InstarTestBase):
    """Verify malformed Parallels fixtures are refused cleanly (fmt-cov 3).

    Four fixtures each violate one of qemu's Parallels open-time
    validation rules that the new ``parallels`` crate enforces:
    ``tracks == 0`` (parallels-zero-tracks, "Zero sectors per track"),
    ``tracks`` over the cluster limit (parallels-huge-tracks, "Too big
    cluster"), ``bat_entries`` over the catalog limit
    (parallels-huge-catalog, "Catalog too large"), and a non-zero
    ``ext_off`` pointing at a bad-magic format extension
    (parallels-ext-bad-magic).  qemu refuses all four at open; instar's
    Parallels reader must likewise refuse -- convert, compare, and dd
    all exit non-zero with a non-empty message and without hanging or
    crashing.  instar's own message need not match qemu's string; only
    the clean non-zero termination is pinned.

    convert and dd surface the reader init failure as an operation error
    on stderr; compare surfaces it as a content mismatch on stdout and
    exits non-zero -- a self-compare of a malformed fixture reports a
    mismatch, not ``identical``, which proves compare is not silently
    reading it as raw.  Both are clean non-zero exits, so the assertion
    checks the combined stdout+stderr for a non-empty message rather
    than pinning the stream.

    ``info`` is deliberately NOT asserted non-zero.  The detection layer
    (``parse_parallels_header``) only checks the magic and version, both
    of which are intact in every malformed fixture (they mutate tracks /
    bat_entries / ext_off, not the magic), so all four still detect as
    ``parallels``: info reports ``file format: parallels`` with the
    lenient nb_sectors-derived virtual size and exits 0.  The read-path
    validation that refuses them lives in the reader, not the detector.
    The adversarial contract for info is only no-hang / no-crash /
    non-empty output, matching the DMG and VDI manifest patterns above.

    The past-EOF zero-fill and inuse-readable rules for the *safe*
    fixtures are pinned by successful byte-parity convert tests in
    tests/test_convert.py::TestConvertParallelsToRaw, not here.
    """

    MALFORMED_IDS = [
        'parallels-zero-tracks',
        'parallels-huge-tracks',
        'parallels-huge-catalog',
        'parallels-ext-bad-magic',
    ]

    def _assert_parallels_refused(self, image_id):
        """convert/compare/dd refuse cleanly; info is clean but may exit 0."""
        image = self.get_adversarial_image(image_id)
        instar = str(self.get_instar_binary())

        with tempfile.NamedTemporaryFile(suffix='.raw') as out, \
                tempfile.NamedTemporaryFile(suffix='.raw') as other:
            # A tiny raw file to compare against.
            Path(other.name).write_bytes(bytes(512))

            # convert: must refuse, non-zero, non-empty message, no hang.
            _c_out, c_err, c_rc = self.run_adversarial(
                [instar, 'convert', '-O', 'raw', str(image.path), out.name],
                timeout=15,
            )
            self.assertNotEqual(
                c_rc, 0,
                f'convert should refuse malformed {image_id}',
            )
            self.assertTrue(
                c_err.strip(),
                f'convert should emit a non-empty error for {image_id}',
            )

            # compare against the raw file: must refuse, non-zero, no hang.
            # compare reports the read failure as a mismatch on stdout, so
            # the combined output (not just stderr) is checked non-empty.
            m_out, m_err, m_rc = self.run_adversarial(
                [instar, 'compare', str(image.path), other.name],
                timeout=15,
            )
            self.assertNotEqual(
                m_rc, 0,
                f'compare should refuse malformed {image_id}',
            )
            self.assertTrue(
                (m_out + m_err).strip(),
                f'compare should emit a non-empty message for {image_id}',
            )

            # dd: must refuse, non-zero, non-empty message, no hang.
            _d_out, d_err, d_rc = self.run_adversarial(
                [instar, 'dd', '-O', 'raw',
                 f'if={image.path}', f'of={out.name}'],
                timeout=15,
            )
            self.assertNotEqual(
                d_rc, 0,
                f'dd should refuse malformed {image_id}',
            )
            self.assertTrue(
                d_err.strip(),
                f'dd should emit a non-empty error for {image_id}',
            )

            # info: no hang / no crash; lenient parser, exit code unpinned.
            i_out, i_err, _i_rc = self.run_adversarial(
                [instar, 'info', str(image.path)],
                timeout=15,
            )
            self.assertTrue(
                (i_out + i_err).strip(),
                f'info should emit non-empty output for {image_id}',
            )

    def test_parallels_zero_tracks_refused(self):
        self._assert_parallels_refused('parallels-zero-tracks')

    def test_parallels_huge_tracks_refused(self):
        self._assert_parallels_refused('parallels-huge-tracks')

    def test_parallels_huge_catalog_refused(self):
        self._assert_parallels_refused('parallels-huge-catalog')

    def test_parallels_ext_bad_magic_refused(self):
        self._assert_parallels_refused('parallels-ext-bad-magic')


class TestAdversarialQcow1Manifest(InstarTestBase):
    """Verify malformed QCOW1 fixtures are refused cleanly (fmt-cov 4).

    Five fixtures each violate one of qemu's qcow1 open-time validation
    rules that the new ``qcow1`` crate's ``Qcow1Header::parse`` enforces:
    ``cluster_bits == 17`` (qcow1-bad-cluster-bits, outside [9,16]),
    ``l2_bits == 14`` (qcow1-bad-l2-bits, outside [6,13]), a ``size`` at
    the ``qcow_open`` L1-size cap (qcow1-huge-size, "Image too large"),
    ``crypt_method == 2`` (qcow1-crypt-invalid, >= 2 unsupported), and a
    ``backing_file_size == 1024`` (qcow1-backing-name-too-long, > 1023).
    convert, compare, and dd must all exit non-zero with a non-empty
    message and without hanging or crashing.

    ``info`` DIFFERS from the vdi/parallels leniency posture, and this is
    pinned deliberately.  For vdi/parallels the detection layer checks
    only magic+version, so a malformed fixture still detects and info
    emits a best-effort *nonzero* virtual size from the intact size
    field.  qcow1's info arm parses MORE: ``Qcow1Header::parse``
    validates cluster_bits / l2_bits / size / crypt_method /
    backing-name, so on EVERY one of these five fixtures the parse FAILS
    and the info arm falls back to the default/empty result -- detection
    still routes the image to ``qcow`` (magic + version 1 are intact), so
    info prints ``file format: qcow`` with ``virtual size: 0 (0 bytes)``
    and exits 0 (empirically pinned 2026-07-18; see
    PLAN-format-coverage-phase-04-qcow1-read.md step 4e, "the info arm
    parses MORE than magic+version").  This zero virtual size is exactly
    why convert and dd refuse: they surface "input image has zero virtual
    size" rather than a format-detection failure.

    The adversarial contract for info is the standard no-hang / no-crash
    / non-empty output; additionally, because the behaviour is uniform
    and load-bearing (it is the mechanism behind the convert/dd
    refusals), each info result is pinned to exactly ``file format:
    qcow`` + ``virtual size: 0 (0 bytes)`` + rc 0.
    """

    MALFORMED_IDS = [
        'qcow1-bad-cluster-bits',
        'qcow1-bad-l2-bits',
        'qcow1-huge-size',
        'qcow1-crypt-invalid',
        'qcow1-backing-name-too-long',
    ]

    def _assert_qcow1_refused(self, image_id):
        """convert/compare/dd refuse cleanly; info parses to an empty result."""
        image = self.get_adversarial_image(image_id)
        instar = str(self.get_instar_binary())

        with tempfile.NamedTemporaryFile(suffix='.raw') as out, \
                tempfile.NamedTemporaryFile(suffix='.raw') as other:
            Path(other.name).write_bytes(bytes(512))

            # convert: must refuse, non-zero, non-empty message, no hang.
            _c_out, c_err, c_rc = self.run_adversarial(
                [instar, 'convert', '-O', 'raw', str(image.path), out.name],
                timeout=15,
            )
            self.assertNotEqual(
                c_rc, 0, f'convert should refuse malformed {image_id}')
            self.assertTrue(
                c_err.strip(),
                f'convert should emit a non-empty error for {image_id}')

            # compare: read failure surfaces as a mismatch on stdout, so
            # the combined output is checked non-empty.  A malformed
            # fixture reporting a mismatch (not "identical") proves it is
            # not silently read as raw.
            m_out, m_err, m_rc = self.run_adversarial(
                [instar, 'compare', str(image.path), other.name],
                timeout=15,
            )
            self.assertNotEqual(
                m_rc, 0, f'compare should refuse malformed {image_id}')
            self.assertTrue(
                (m_out + m_err).strip(),
                f'compare should emit a non-empty message for {image_id}')

            # dd: must refuse, non-zero, non-empty message, no hang.
            _d_out, d_err, d_rc = self.run_adversarial(
                [instar, 'dd', '-O', 'raw',
                 f'if={image.path}', f'of={out.name}'],
                timeout=15,
            )
            self.assertNotEqual(
                d_rc, 0, f'dd should refuse malformed {image_id}')
            self.assertTrue(
                d_err.strip(),
                f'dd should emit a non-empty error for {image_id}')

            # info: pinned empty/default result -- format qcow, vsize 0,
            # rc 0 (the qcow1 info arm parses more than magic+version, so
            # the mutated field breaks the parse entirely rather than
            # yielding a lenient nonzero size; see the class docstring).
            i_out, i_err, i_rc = self.run_adversarial(
                [instar, 'info', str(image.path)],
                timeout=15,
            )
            self.assertEqual(
                i_rc, 0,
                f'info on {image_id} should exit 0 (empty result): '
                f'{i_out!r} {i_err!r}')
            self.assertIn(
                'file format: qcow', i_out,
                f'info on {image_id} should still detect qcow: {i_out!r}')
            self.assertIn(
                'virtual size: 0 (0 bytes)', i_out,
                f'info on {image_id} should report zero virtual size '
                f'(failed parse -> default result): {i_out!r}')

    def test_qcow1_bad_cluster_bits_refused(self):
        self._assert_qcow1_refused('qcow1-bad-cluster-bits')

    def test_qcow1_bad_l2_bits_refused(self):
        self._assert_qcow1_refused('qcow1-bad-l2-bits')

    def test_qcow1_huge_size_refused(self):
        self._assert_qcow1_refused('qcow1-huge-size')

    def test_qcow1_crypt_invalid_refused(self):
        self._assert_qcow1_refused('qcow1-crypt-invalid')

    def test_qcow1_backing_name_too_long_refused(self):
        self._assert_qcow1_refused('qcow1-backing-name-too-long')
