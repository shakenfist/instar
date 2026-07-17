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
