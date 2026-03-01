# Plan: imago convert — Phases 8+

## Context

Phases -1 through 7 are complete (see PLAN-convert.md and
PLAN-convert-phase7.md). imago supports QCOW2 and raw input/output
for convert, compare, and check. This plan covers the remaining
format support and cross-tool validation work.

**Scope decisions:**
- Phase 8: VMDK input/output. Complete.
- Phase 9: VHD input+output (dynamic VHD with BAT).
- Phase 10: VHDX input+output.
- Phase 11: oslo.utils format_inspector cross-validation testing.
- Phase 12: LUKS container inspection (inner format detection with
  passphrase).

---

## Phase 8: VMDK Input+Output

Please commit each sub-phase before moving onto the next one.

### 8a: Extend vmdk crate with grain directory/table reading

**Files:** `src/crates/vmdk/src/lib.rs`, `src/crates/vmdk/Cargo.toml`

Extend `Vmdk4Header` (or add `Vmdk4HeaderFull`) to parse the full 512-byte
header: `flags`, `num_gtes_per_gt`, `rgd_offset`, `gd_offset`,
`overhead`, `compressAlgorithm`. Add flag constants (`FLAG_ZERO_GRAIN`,
`FLAG_COMPRESSED`, `GD_AT_END`, `GTE_ZEROED`).

Add `VmdkState` struct (analogous to `Qcow2State`):
- Device index, grain size, GD offset, num GD entries, flags
- Two sector caches (GD + GT), same pattern as QCOW2's L1/L2 caches

Add `GrainLookup` enum: `Unallocated`, `Zeroed`, `Standard(u64)`,
`Compressed(u64)`.

Implement `VmdkState::init()` (reads+parses header, validates, sets up
caches) and `VmdkState::grain_lookup()` (two-level GD→GT address
translation using `read_u32_le_cached()`).

Unit tests for header parsing, grain count calculations, invalid header
rejection.

### 8b: VMDK monolithicSparse input in convert and compare

**Files:** `src/crates/qcow2/src/lib.rs`, `src/crates/qcow2/Cargo.toml`,
`src/operations/convert/Cargo.toml`, `src/operations/convert/src/main.rs`,
`src/operations/compare/Cargo.toml`, `src/operations/compare/src/main.rs`

Add `vmdk-input` feature to qcow2 crate, gating an optional dependency on
the vmdk crate.

Introduce `ChainStates` struct bundling `qcow2_states` and
`vmdk_states` arrays to keep the chain reader signature clean and
extensible. Refactor `init_chain_qcow2_states` → `init_chain_states`
to initialize both. Refactor `read_chain_virtual_cluster` to accept
`ChainStates` and add a `#[cfg(feature = "vmdk-input")]` arm for
`ImageFormat::Vmdk4` that calls `vmdk_state.grain_lookup()` and reads
grain data via `read_cluster_sectors()`.

Enable `vmdk-input` in convert and compare Cargo.toml. Update both
operations to use `ChainStates`.

Accept `-f vmdk` / auto-detect VMDK in VMM for convert input.

**Tests:** Convert plaso-vmdk and vmdk-multi-partition to raw, cross-
validate with qemu-img. Compare VMDK vs qemu-img-converted raw.

### 8c: streamOptimized VMDK input (DEFLATE decompression)

**Files:** `src/crates/vmdk/src/lib.rs`, `src/crates/vmdk/Cargo.toml`,
`src/crates/qcow2/src/lib.rs`

Add `decompress` feature to vmdk crate (depends on `miniz_oxide`).

In `VmdkState::init()`: detect `gd_offset == GD_AT_END`, read footer
(3 sectors from EOF), parse footer header to get real GD offset.

Add `read_compressed_grain()`: reads 12-byte grain marker (u64 lba LE +
u32 size LE), reads compressed data, decompresses with miniz_oxide
raw DEFLATE (same algorithm as QCOW2 zlib).

Extend the `Vmdk4` arm in `read_chain_virtual_cluster` for the
`GrainLookup::Compressed` case.

Enable vmdk `decompress` feature in convert/compare.

**Tests:** Convert vmdk-streamoptimized to raw, cross-validate with
qemu-img.

### 8d: VMDK monolithicSparse output in convert

**Files:** `src/crates/vmdk/src/lib.rs`, `src/operations/convert/src/main.rs`,
`src/shared/src/lib.rs`, VMM output format handling

Add write helpers to vmdk crate behind `write` feature: `write_le_u32`,
`write_le_u64`, `build_sparse_header()`, descriptor formatting.

Output layout:
```
[0]          Header (512 bytes)
[512]        Descriptor (~10KB, padded to sector)
[desc_end]   Grain Directory (u32 LE entries)
[gd_end]     Grain Tables (512 x u32 LE each)
[gt_end]     Grain data (sequential)
```

Add `convert_to_vmdk()` in convert operation:
1. Reserve space for header + descriptor + GD + GTs
2. Write grain data sequentially (like QCOW2 linear allocation)
3. Build and write GD/GT entries as grains are written
4. Write descriptor and header last (with final metadata)

Accept `-O vmdk` in VMM. Add `ImageFormat::Vmdk4` to
`ConvertConfig::target_format()`.

**Tests:** Raw→VMDK, QCOW2→VMDK, round-trip (VMDK→raw→VMDK→raw),
verify with qemu-img info and qemu-img check.

### 8e: streamOptimized VMDK output (compressed, with -c flag)

**Files:** `src/crates/vmdk/src/lib.rs`, `src/operations/convert/src/main.rs`

Add `compress` feature to vmdk crate (miniz_oxide with alloc).

streamOptimized output layout:
```
[0]          Header (gd_offset = GD_AT_END)
[512]        Descriptor
[desc_end]   Grain markers + DEFLATE compressed data
[...]        GD + GTs
[...]        Footer (header copy with real GD offset)
[EOF]        EOS marker
```

Add `convert_to_vmdk_compressed()`: writes grain markers (12 bytes each)
+ DEFLATE compressed data, then GD/GT/footer/EOS at end.

Triggered by `-O vmdk -c` (same as QCOW2 compressed output).

**Tests:** Convert with `-c` flag, verify output is streamOptimized
via qemu-img info. Round-trip compressed VMDK→raw, compare.

### 8f: Enhanced VMDK check with GD/GT validation

**Files:** `src/operations/check/Cargo.toml`,
`src/operations/check/src/main.rs`

Replace current basic header-only `check_vmdk()` with full structural
check:
1. Parse full header via vmdk crate
2. Validate GD offset within file bounds
3. Read each GD entry, validate GT offsets
4. Read each GTE, validate grain offsets within file
5. Overlap detection via 1-bit-per-grain bitmap (same pattern as QCOW2)
6. For streamOptimized: validate footer, grain marker consistency
7. Multi-extent detection: parse descriptor, error if multiple extents

**Tests:** Check clean VMDK images (0 errors), check corrupt images,
check streamOptimized.

### 8g: Integration tests and documentation

Manifest-driven tests: convert all VMDK test images to raw, cross-validate.
VMDK→QCOW2→raw round-trips. Compare tests. Update README.md,
ARCHITECTURE.md, AGENTS.md, format-coverage.md.

Fix two omissions in `docs/chain-discovery.md`:
- Line 178: Remove "Future Work" item about convert flattening backing
  chains — this was implemented in Phase 3.
- Lines 159-174: Add `imago convert` to the "Operations Using Chain
  Discovery" section (it discovers backing chains and loads all chain
  images as separate virtio-block devices for flattening).

---

## Phase 9: VHD Input+Output

Please commit each sub-phase before moving on.

### 9a: Create vhd crate with footer/dynamic header/BAT parsing

**New files:** `src/crates/vhd/Cargo.toml`, `src/crates/vhd/src/lib.rs`

Add to workspace in `src/Cargo.toml`.

`no_std` crate with:
- `VhdFooter::parse()`: 512-byte footer (big-endian fields: cookie,
  data_offset, original_size, current_size, geometry, disk_type, checksum)
- `VhdDynamicHeader::parse()`: 1024-byte dynamic header ("cxsparse"
  cookie, table_offset, max_table_entries, block_size)
- `VhdState` struct: device_idx, disk_type, block_size,
  block_data_offset (sector bitmap size), max_table_entries,
  table_offset, current_size, BAT sector cache + data sector cache
- `VhdState::init()`: reads footer (first or last sector), dynamic
  header, validates
- `BlockLookup` enum: `Unallocated`, `Allocated { host_byte_offset }`
- `VhdState::block_lookup()`: reads BAT entry (u32 BE, 0xFFFFFFFF =
  unallocated), returns host offset to block data (past sector bitmap)

Fixed VHD handling: `disk_type == 2` means raw data from offset 0 to
EOF-512. Treat as raw in the chain reader.

Unit tests for footer/header parsing, BAT lookup, geometry.

### 9b: VHD input in convert and compare

**Files:** `src/crates/qcow2/src/lib.rs`, `src/crates/qcow2/Cargo.toml`,
`src/operations/convert/Cargo.toml`, `src/operations/convert/src/main.rs`,
`src/operations/compare/Cargo.toml`, `src/operations/compare/src/main.rs`

Add `vhd-input` feature to qcow2 crate. Extend `ChainStates` with
`vhd_states` array. Add `ImageFormat::Vhd` arm in
`read_chain_virtual_cluster`:
- `Unallocated` → continue to next chain device
- `Allocated` → read block data at host offset (past sector bitmap)
- Fixed VHD → read raw sectors directly

Enable `vhd-input` in convert and compare.

**Tests:** Convert hyperv-dynamic-vhd, virtualpc-vhd, vhd-d2v-zerofilled
to raw, cross-validate. Compare VHD vs raw.

### 9c: VHD dynamic output in convert

**Files:** `src/crates/vhd/src/lib.rs`, `src/operations/convert/src/main.rs`,
`src/shared/src/lib.rs`, VMM output format handling

Add write support behind `write` feature: `build_footer()`,
`build_dynamic_header()`, `compute_vhd_geometry()` (matching VPC
algorithm), `compute_footer_checksum()`.

Output layout:
```
[0]          Footer copy (512 bytes)
[512]        Dynamic header (1024 bytes)
[1536]       BAT (max_table_entries * 4, padded to sector)
[bat_end]    Block data (sector bitmap + data per block)
[EOF-512]    Footer (512 bytes)
```

Add `convert_to_vhd()`: write header/BAT placeholder, write blocks
sequentially (sector bitmap with all-1s + data), rewrite BAT with
actual offsets, write final footer.

Accept `-O vpc` in VMM (matching qemu-img's name for VHD format).

**Tests:** Raw→VHD, QCOW2→VHD, round-trip, verify with qemu-img.

### 9d: Enhanced VHD check with BAT validation

**Files:** `src/operations/check/Cargo.toml`,
`src/operations/check/src/main.rs`

Enhance VHD check:
1. Parse footer + dynamic header
2. Validate BAT offset within file
3. Read BAT entries, validate block offsets within file
4. Overlap detection (no two BAT entries should overlap)
5. Footer checksum validation
6. Footer cookie match at start and end of file

**Tests:** Check clean VHD images, check corrupt/malformed VHD images.

### 9e: Integration tests and documentation

Manifest-driven VHD tests. Round-trip tests. Update README.md,
ARCHITECTURE.md, AGENTS.md, format-coverage.md.

## Phase 10: VHDX input+output — COMPLETE

Implemented full VHDX support in 5 sub-phases:

- **Phase 10a**: VHDX crate (`src/crates/vhdx/`) with CRC-32C (Castagnoli)
  implementation, header/region table/metadata parsing, BAT reading with
  interleaved sector bitmap entries, VhdxState for block I/O, and output
  builders. ~1400 lines, 19 unit tests.
- **Phase 10b**: VHDX input support in convert and compare operations via
  `vhdx-input` feature gate in qcow2 crate chain reader.
- **Phase 10c**: VHDX dynamic output in convert operation. 32 MiB blocks,
  1MB-aligned structures, CRC-32C checksums, skip-zeros support.
- **Phase 10d**: Enhanced VHDX check with comprehensive validation: dual
  header CRC-32C, dirty log detection, region table CRC, GUID-based
  metadata parsing, BAT bounds/alignment/overlap/state validation.
- **Phase 10e**: Integration tests (VHDX→raw, raw→VHDX, round-trip,
  compare, check output) and documentation updates.
- **Phase 10f** (fix): VMM cluster_size check excluded VHD/VHDX
  (block_size ≠ cluster_size), and VHDX output capacity calculation
  accounts for 32MB block rounding.

## Deferred Work (from Phase 10 review)

### Refactoring Opportunities (not blocking, future improvement)

17. **Byte-order helper duplication grows** — VHDX adds LE helpers
    (`le_u16`/`le_u32`/`le_u64`, `write_le_*`) duplicating the
    pattern from VHD's LE and QCOW2/VMDK's BE helpers. All format
    crates have ~20 lines of identical byte-order helpers. Still
    not blocking — same recommendation as item 11.

18. **Two-pass zero check in convert_to_vhdx** — Same pattern as
    item 12 (VHD). Each 32 MiB VHDX block is read twice when
    skip-zeros is enabled. Performance impact is minimal for
    typical images due to OS page cache.

---

## Phase 11: oslo.utils format_inspector Cross-Validation ✓

**Status:** Complete (March 2026)

### 11a: Add oslo.utils to test dependencies ✓

Added `oslo.utils>=8.0.0` to `tests/requirements.txt`. Installed
automatically in CI via `make test-container`.

### 11b: format_inspector cross-validation test class ✓

`tests/test_oslo_crossval.py` — three test classes with 128 tests:

- **TestOsloFormatDetection** — compares format names (with
  `IMAGO_TO_OSLO_FORMAT` mapping for vpc→vhd)
- **TestOsloSafetyCheck** — cross-validates backing_file and
  data_file safety flags between tools
- **TestOsloVirtualSize** — compares virtual size (with CHS
  rounding tolerance for VPC format)

Documented divergences in module constants:
- GPT detection: oslo detects MBR/GPT raw images as 'gpt'
- QED banning: oslo always rejects QED; imago uses KVM sandbox
- LUKS: oslo rejects v2+; imago detects both versions
- External data file: imago detects feature bit but does not
  expose data-file path in JSON output
- ISO/LUKS format names: imago reports 'raw'/'unknown'

### 11c: CI integration ✓

Added `oslo-crossval-master` job to
`.github/workflows/functional-tests.yml`. Installs oslo.utils from
git master, runs crossval tests only, `continue-on-error: true`.

### 11d: Documentation ✓

Updated `docs/format-coverage.md`, `README.md`, `ARCHITECTURE.md`,
`AGENTS.md` with oslo.utils crossval documentation.

---

## Phase 12: LUKS Container Inspection

### Motivation

oslo.utils is adding LUKS inner format detection (review 978097):
when given a LUKS image and a passphrase, it decrypts the first
block to identify the inner format (GPT, QCOW2, etc.) and cascades
safety checks through. imago should offer equivalent functionality
so OpenStack deployments can make informed decisions about LUKS
images.

imago already detects LUKS format and version in `imago info`. This
phase adds inner format reporting when a passphrase is provided.

### 12a: LUKS test images

**Files:** `tests/manifest.json`, test image generation scripts

Create test images:
- `luks-v1-gpt`: LUKS v1 wrapping a GPT-partitioned raw image
- `luks-v1-qcow2`: LUKS v1 wrapping a QCOW2 image
- `luks-v2-gpt`: LUKS v2 wrapping a GPT-partitioned raw image

Use `cryptsetup luksFormat` with known passphrases. Store the
passphrase in the manifest (test-only, not secret). Mark these
with `skip_qemu_img: true` since qemu-img doesn't inspect inside
LUKS without a secret object.

### 12b: LUKS header parsing in info operation

**Files:** `src/shared/src/lib.rs`, `src/operations/info/src/main.rs`

Extend the existing LUKS detection in the info operation to parse:
- Version (already detected)
- Cipher name, cipher mode, hash algorithm
- Payload offset (where encrypted data starts)
- Key slot status (which slots are active)

Report these as structured fields in the JSON output, similar to
how QCOW2 reports cluster_size and backing_file.

### 12c: LUKS decryption in VMM (passphrase handling)

**Files:** `src/vmm/src/main.rs`, `src/shared/src/lib.rs`

Add `--luks-passphrase` flag (or `--secret` matching qemu-img's
pattern). The VMM:
1. Reads the passphrase
2. Passes it to the guest via operation config
3. Guest decrypts the first block of payload data
4. Guest runs format detection on decrypted data
5. Reports inner format in the info result

**Security considerations:**
- Passphrase only held in VMM memory, passed to guest via config
  area (which is in guest-private memory)
- No need to decrypt the full image — just the first sector/block
  for format detection
- KVM sandbox prevents the guest from leaking the passphrase

### 12d: LUKS inner format in imago info output

**Files:** `src/vmm/src/main.rs`, output formatting

When a LUKS image is detected and a passphrase is provided, the
info output includes an `inner_format` field:

```json
{
    "format": "luks",
    "version": 1,
    "cipher": "aes-xts-plain64",
    "inner_format": "gpt",
    "inner_virtual_size": 10737418240
}
```

Without a passphrase, `inner_format` is omitted (matching current
behaviour where we just report "luks").

### 12e: Documentation and oslo.utils cross-validation

Update docs/format-coverage.md with LUKS inner format support.
Add LUKS cross-validation to Phase 11 tests (compare imago's
inner format detection with oslo.utils LUKSInspector).

### Design Notes

**LUKS v1 vs v2:** oslo.utils currently only supports v1. imago
should start with v1 for parity. v2 uses a different header format
(JSON-based metadata) and different key derivation (Argon2id),
which would need additional implementation.

**Crypto in no_std guest:** The decryption must run inside the KVM
guest (no_std, bare-metal). Options:
- Implement PBKDF2 + AES-XTS from first principles (small code,
  but needs careful review)
- Use a no_std crypto crate like `aes` + `pbkdf2` from RustCrypto
  (well-audited, but adds binary size)
- Perform decryption in the VMM instead (simpler, but breaks the
  "all format parsing in the sandbox" security model)

The VMM-side approach is pragmatic for a first implementation since
LUKS header parsing is simple and the passphrase is already trusted
input. The guest-side approach is more consistent with imago's
security model and should be the long-term goal.

---

## Key Architectural Decisions

**ChainStates refactor**: Bundle qcow2/vmdk/vhd state arrays into a
single struct passed to the chain reader. Feature-gated fields keep
binary size small when formats aren't needed.

**Reuse existing patterns**: VMDK grain lookup mirrors QCOW2 cluster
lookup (two-level table, sector-cached reads). VHD block lookup is
simpler (single-level BAT). Both follow the established `State::init()`
+ `State::lookup()` + cache pattern.

**VMDK DEFLATE reuse**: streamOptimized uses raw DEFLATE, same as
QCOW2 compression. miniz_oxide is already linked; LTO deduplicates.

**Multi-extent VMDKs**: Detected via descriptor parsing. Graceful error:
"multi-extent VMDK not supported". Future path: parse extent lines in
guest, report to VMM, VMM opens each extent as a device with sector-
range mapping in ChainConfig. This needs to provide opportunity for
the user to agree that each file is safe to add to the VMM, much like
the qcow2 chain discovery / attachment flow.

## Risks

- **Binary size**: Adding miniz_oxide to vmdk crate may push convert
  binary close to 384KB. Monitor after each sub-phase. miniz_oxide is
  already linked for QCOW2, so LTO should deduplicate.
- **VMDK v3**: Version 3 VMDKs may have different GD/GT semantics.
  Test with vmdk-v3 image. qemu opens v3 as read-only.
- **VHD geometry quirks**: VPC CHS algorithm has edge cases. Must match
  VPC's exact algorithm for cross-compatibility.
- **Large BAT**: For multi-TB VHDs, BAT can be millions of entries.
  Cannot buffer entirely in scratch memory. Use sector-by-sector I/O.
- **streamOptimized footer**: Footer at fixed offset from EOF. Need to
  handle sector size alignment when reading footer sectors.

## Phase 8 Completion Status

Phase 8 (VMDK) is complete. All sub-phases 8a-8g committed.

## Phase 9 Completion Status

Phase 9 (VHD) is complete. All sub-phases 9a-9e committed.

## Deferred Work (from Phase 9 review)

### Refactoring Opportunities (not blocking, future improvement)

11. **Byte-order helper duplication** — `be_u16`/`be_u32`/`be_u64`
    and `write_be_*` helpers are duplicated across qcow2, vmdk,
    and vhd crates (~130 lines total). Could be moved to shared
    crate. Pre-existing pattern; VHD followed the convention.

12. **Two-pass zero check in convert_to_vhd** — When skip-zeros
    is enabled, VHD output reads each 2 MiB block twice: once to
    check if all-zeros, once to write. This is a memory vs I/O
    tradeoff (block is 2 MiB but I/O buffer is 64 KB, so the
    entire block can't be buffered). Performance impact is minor
    for typical images. Could be optimized with a streaming
    approach that buffers results across chunks.

### Test Gaps (Phase 9)

13. **No VHD convert integration tests** — No tests for VHD→raw,
    raw→VHD, QCOW2→VHD, or VHD→QCOW2 conversion round-trips.
    VMDK has full round-trip coverage (TestConvertVmdkToRaw,
    TestConvertToVmdk, TestConvertVmdkToQcow2Roundtrip,
    TestConvertVmdkCheckOutput). VHD needs equivalent tests.

14. **No VHD compare integration tests** — No tests comparing
    VHD vs raw equivalence after conversion. VMDK has
    TestConvertVmdkCompare for this.

15. **No fixed VHD test image** — All VHD test images are
    dynamic. No fixed VHD (disk_type=2) test image exists.

16. **No differencing VHD test image** — Code handles
    disk_type=4 (differencing) in check, but no test image
    exercises this path.

## Deferred Work (from Phase 8 review)

### Refactoring Opportunities (not blocking, future improvement)

1. **Consolidate cached-read helpers** — DONE. Extracted `cached_read!`
   macro to shared crate (commit 069fea0). ~180 lines eliminated.

2. **Chain state init boilerplate** — Already extracted to
   `init_chain_states()` in qcow2 crate. Per-operation feature
   validation is intentionally different, so no further extraction.

3. **Bitmap overlap detection** — DONE. Extracted `shared::bitmap`
   module with `BitmapContext` struct (commit 069fea0). ~50 lines
   eliminated from check operation.

### Test Gaps (pre-existing, not Phase 8 regressions)

4. **Unused malformed VMDK test images** — `afl-vmdk-l1-too-big`,
   `vmdk-path-traversal`, `vmdk-no-extents` are in the manifest with
   `run_in_ci=false` (not available in CI). Consider making them available
   or adding local-only tests.

5. **Security test placeholders** — `test_imago_handles_vmdk_descriptor_safely`
   and `test_imago_does_not_follow_external_data` are SKIPPED with "not yet
   implemented". These need the security test framework to be built out.

6. **Multi-extent VMDK tests** — No test images exercise the multi-extent
   detection and error path. Would need a multi-extent test image.

### oslo.utils format_inspector developments (Feb 2026)

Gerrit review 978095 and related changes show oslo.utils is adding:

7. **ContainerFileInspector** (978095, NEW) — New base class for
   formats that wrap other formats. Adds `inner_format` property
   and cascading `inner_safety` check. LUKS is the first user.

8. **LUKS decryption inspector** (978097, WIP) — LUKSInspector now
   inherits from ContainerFileInspector and can decrypt the first
   block of a LUKS image (with passphrase) to detect the inner
   format (GPT, QCOW2, etc.) and cascade safety checks. Uses
   PBKDF2 key derivation, AFsplit/merge, and AES-XTS decryption.
   Claude Sonnet 4.5 generated the decryption code per Dan Smith.

9. **Data parameter for inspectors** (978096, NEW) — Adds a `data`
   dict parameter to FileInspector, allowing callers to pass
   supplemental info (e.g., LUKS passphrase) without altering
   safety check behavior.

10. **GPT/MBR safety check cleanup** (938679, NEW) — Splits baseline
    MBR checks from GPT-specific rules, adds comments, makes it
    easier to selectively loosen rejections.

**Implications for imago:**
- imago already detects LUKS format but doesn't inspect inner
  content. If OpenStack starts cascading safety checks through
  LUKS containers, imago should consider reporting the inner
  format too (though our KVM sandbox makes this less critical).
- The GPT/MBR safety check reorganization may change oslo.utils
  output format; monitor for test compatibility impact.
- The `ContainerFileInspector` pattern is worth noting if we add
  LUKS support to `imago convert` — we'd need similar chained
  format detection in the guest.

## Verification

After each sub-phase:
1. `pre-commit run --all-files` (formatting/clippy)
2. `make imago` (build)
3. `scripts/check-binary-sizes.sh` (384KB limit)
4. `cd tests && ../.venv/bin/stestr run <pattern>` (relevant tests)
5. Full suite: `cd tests && ../.venv/bin/stestr run`
