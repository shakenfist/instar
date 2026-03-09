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
- Phase 14: Byte-order consolidation & VHD integration tests.
- Phase 15: Test coverage gaps & minor optimizations.

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

17. **Byte-order helper duplication grows** — DONE (Phase 14a,
    same as item 11). All helpers consolidated in shared crate.

18. **Two-pass zero check in convert_to_vhdx** — DONE (Phase 15e).
    Same fix as item 12: `break` after `block_all_zeros = false`.

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

## Phase 12: LUKS Container Inspection ✓

**Status:** Complete (March 2026)

### 12a: LUKS test images ✓

Synthetic LUKS headers generated by `scripts/create-luks-headers.py`
(v1: 592 bytes, v2: 16 KiB with JSON metadata). Real LUKS containers
created by `scripts/create-luks-testdata.sh` using cryptsetup:
luks-v1-raw-gpt (wrapping GPT raw) and luks-v1-qcow2 (wrapping QCOW2).
Test passphrases stored in manifest with `skip_qemu_img: true`.

### 12b: LUKS header parsing in info operation ✓

Extended info operation to parse LUKS v1/v2 headers: cipher name,
cipher mode, hash algorithm, UUID, payload offset, master key length,
active key slots. Added `LuksInfo` struct to shared crate. Protobuf
`LuksInfo` message for guest-to-VMM reporting. JSON output includes
all LUKS metadata fields.

### 12c: Guest-side LUKS1 decryption ✓

Added `--luks-passphrase` flag. Passphrase passed via operation config.
Guest decrypts using pure-Rust RustCrypto crates (pbkdf2, aes, hmac,
sha1, sha2, xts-mode) with software AES (cfg `aes_force_soft` for
bare-metal x86_64-unknown-none). AFsplit/merge key recovery. Decrypted
first block passed through format detection to identify inner format.

### 12d: Inner format in imago info output ✓

Added `inner_format` and `inner_virtual_size` fields to LuksInfo.
Inner virtual size extracted from decrypted header: QCOW2 (offset 24,
big-endian u64), Raw (device capacity - payload offset). VMM JSON
output conditionally includes inner format fields when decryption
succeeds.

### 12e: LUKS v2 metadata and --max-guest-memory ✓

Added `--max-guest-memory` CLI flag (infrastructure for future Argon2id
support). LUKS v2 JSON metadata parsing extracts cipher/hash/key_size
from keyslots and segments sections using pattern scanning (no full
JSON parser in no_std). Fixed LUKS v2 test header generator to match
LUKS2 on-disk format spec v1.1 (UUID at offset 168, salt 64 bytes,
JSON area at offset 4096).

### 12f: Documentation ✓

Updated format-coverage.md, README.md, ARCHITECTURE.md, AGENTS.md
with LUKS support documentation. Marked Phase 12 complete.

## Phase 13: QCOW2 External Data File Support ✓

QCOW2 v3 allows separating metadata (L1/L2 tables, refcounts) from
cluster data via the "external data file" feature (incompatible bit 2).
Full read support: info reports the data file path, check/convert/compare
process images when the data file is provided via `--chain`.

### 13a: Parse DATA header extension and expose path ✓

Added `EXT_EXTERNAL_DATA_FILE` constant (0x44415441) and refactored
`parse_header_extensions()` to return `HeaderExtensionResults` with both
backing format and data file name. Info operation extracts data file name
and passes it to VMM. Human output: `data file: <path>`. JSON output:
`data-file` in `format-specific.data`.

### 13b: VMM-side data file discovery and device setup ✓

Chain discovery validates external data file path against allowlist
(CVE-2024-32498). Data file opens as device 1, backing chain shifts to
devices 2+. `ChainDeviceInfo.data_device_idx` field (replaces `_reserved`)
tells the guest which device holds cluster data. `ChainConfig.VERSION`
bumped to 2. Helper functions `write_chain_device_entries()` and
`open_chain_devices()` used across convert, check, and compare operations.

### 13c: Guest-side cluster read dispatch ✓

`INCOMPAT_EXTERNAL_DATA` added to `SUPPORTED_INCOMPAT_FEATURES` in both
`#[cfg]` variants. `read_chain_virtual_cluster()` dispatches standard
cluster reads to `data_device_idx` when non-zero. Compressed clusters and
L1/L2 table reads stay on the metadata device. Check operation's supported
features mask updated.

### 13d: Test images and integration tests ✓

Fixed check operation to skip bounds/overlap/refcount validation for
standard cluster data offsets when external data bit is set. Created
`scripts/create-external-data-testdata.sh` for test image generation.
Added `qcow2-external-data-raw` to manifest. Implemented security tests
(`test_imago_reports_external_data_file_without_reading_content`,
`test_imago_reports_external_data_file_in_json`). Added check integration
tests (`TestCheckExternalDataFile` class).

### 13e: Oslo crossval and documentation ✓

Removed `qcow2-external-data-file` from `KNOWN_SAFETY_DIVERGENCES` — imago
now reports the data-file path in JSON, resolving the oslo crossval
divergence. Updated format-coverage.md (feature bit table, capabilities
list, divergences table), ARCHITECTURE.md (QCOW2 features), README.md,
AGENTS.md.

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

11. **Byte-order helper duplication** — DONE (Phase 14a). Moved all
    12 helpers to shared crate, updated ~30 call sites.

12. **Two-pass zero check in convert_to_vhd** — DONE (Phase 15e).
    Added `break` after `block_all_zeros = false` to bail early
    when first non-zero chunk is found, avoiding up to 31
    unnecessary reads per block.

### Test Gaps (Phase 9)

13. **No VHD convert integration tests** — DONE (Phase 14b-14d).
    Added TestConvertVhdToRaw, TestConvertToVhd,
    TestConvertVhdCheckOutput, TestConvertVhdToQcow2Roundtrip.

14. **No VHD compare integration tests** — DONE (Phase 14d).
    Added TestConvertVhdCompare.

15. **No fixed VHD test image** — DONE (Phase 15b). Synthetic
    10 MiB fixed VHD with MBR signature and 0xBE pattern.

16. **No differencing VHD test image** — DONE (Phase 15d).
    Dynamic VHD patched to disk_type=4 exercises
    DISK_TYPE_DIFFERENCING acceptance.

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

5. **Security test placeholders** — DONE (Phase 13d + 15a).
   External data test done in Phase 13d. VMDK descriptor security
   test done in Phase 15a (text-only descriptors rejected as
   unknown format — correct security behavior).

6. **Multi-extent VMDK tests** — DONE (Phase 15c). Synthetic
   binary VMDK4 with two extent lines exercises
   `count_extent_lines()` and FLAG_NOT_SUPPORTED path.

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
- imago now reports LUKS inner format when given a passphrase,
  matching oslo.utils ContainerFileInspector functionality.
- The GPT/MBR safety check reorganization may change oslo.utils
  output format; monitor for test compatibility impact.

## Phase 14: Byte-Order Consolidation & VHD Integration Tests ✓

Consolidate duplicate byte-order helpers from format crates into the
shared crate, add comprehensive VHD integration tests, and fix VHD
sector alignment bugs discovered during testing.

### 14a: Byte-order helper consolidation ✓

Moved all 12 byte-order helpers (`be_u16/32/64`, `le_u16/32/64`,
`write_be_u16/32/64`, `write_le_u16/32/64`) from qcow2, vhd, vhdx,
and vmdk crates into `src/shared/src/lib.rs`. Updated ~30 call sites
in the convert operation. Eliminates ~120 lines of duplication.

### 14b: VHD-to-raw conversion tests ✓

Added `TestConvertVhdToRaw` class testing conversion of hyperv-dynamic,
virtualpc, and d2v-zerofilled VHD images to raw with qemu-img
cross-validation.

### 14c: VHD round-trip and check-output tests ✓

Added `TestConvertToVhd` (raw/qcow2/VHD → VHD → raw round-trip) and
`TestConvertVhdCheckOutput` (structural integrity of imago-produced VHD).

### 14d: VHD compare and cross-format round-trip tests ✓

Added `TestConvertVhdCompare` (VHD vs raw baseline) and
`TestConvertVhdToQcow2Roundtrip` (VHD → QCOW2 → raw). All tests
include temp space checks for large images.

### 14e: Bug fixes discovered during testing ✓

- **VHD read sector alignment**: VHD BAT entries use 512-byte sector
  addressing, but the device sector size can be 65536 bytes. Added
  `read_offset_sectors()` to handle sub-sector-aligned reads for VHD
  data that starts mid-sector.
- **VHD write sector alignment**: When writing VHD output, the bitmap
  (512 bytes) and data share the same output sector (65536 bytes).
  Separate writes clobbered each other. Fixed with carry-buffer approach
  that assembles bitmap+data into sector-aligned writes using a read
  buffer for input I/O and a carry buffer for the 512-byte leftover
  between output sectors.

## Phase 15: Test Coverage Gaps & Minor Optimizations ✓

**Status:** Complete (March 2026)

Addresses six deferred work items from Phases 8–10 reviews.

### 15a: VMDK descriptor security test ✓

Un-skipped `test_imago_handles_vmdk_descriptor_safely` and implemented
the test body. Text-only VMDK descriptors are correctly rejected as
unknown format (no binary magic = no VMDK parsing = no extent path
following). Added `test_imago_handles_vmdk_no_extents_safely`.

### 15b: Fixed VHD test image ✓

Created `scripts/create-vhd-testdata.sh` generating a 10 MiB fixed VHD
(disk_type=2) with MBR signature and 0xBE data pattern. Added check and
convert tests exercising `init_fixed()`.

### 15c: Multi-extent VMDK test ✓

Created `scripts/create-vmdk-testdata.sh` generating a synthetic binary
VMDK4 with two extent lines. Exercises `count_extent_lines()` and the
FLAG_NOT_SUPPORTED early-bail path in check.

### 15d: Differencing VHD test image ✓

Extended VHD testdata script to create a differencing VHD (disk_type=4)
by patching a qemu-img dynamic VHD. Exercises DISK_TYPE_DIFFERENCING
acceptance in `VhdState::init()`.

### 15e: VHD/VHDX skip-zeros bail-early ✓

Added `break` after `block_all_zeros = false` in both VHD and VHDX
zero-check loops. Avoids reading up to 31 (VHD) or 511 (VHDX)
unnecessary chunks per data-heavy block.

### 15f: Documentation ✓

Updated `docs/format-coverage.md` with new test images. Marked deferred
items 5, 6, 12, 15, 16, 18 as done in this file.

---

## Deferred Work (from Phase 12 review)

### Future LUKS Enhancements

19. **LUKS v2 Argon2id decryption** — LUKS v2 uses Argon2id for
    key derivation, which requires significant memory (typically
    1 GiB). The current 32 MiB guest allocation is insufficient.
    The `--max-guest-memory` CLI flag provides infrastructure;
    implementation requires dynamic page table expansion in the
    VMM and guest, plus integrating an Argon2 crate (no_std).

20. **LUKS v2 test container** — `luks-v2-raw-gpt` is defined
    in the manifest but not yet created (cryptsetup v2 format
    requires Argon2 for key derivation, which is slow in CI).
    Create when v2 decryption is implemented.

21. **LUKS convert support** — Currently LUKS is info-only.
    Future: `imago convert --luks-passphrase` could decrypt
    LUKS and convert the inner image in a single pass.

### Format Capability Gaps

22. ~~**Compressed clusters >64KB**~~ — **Done (Phase 16a).**
    Added 2MB decompression staging buffer. Compressed clusters
    up to 2MB are now decompressed via a staging buffer, with
    chunk-level caching to avoid re-decompression. The 128KB
    compressed input buffer limit still applies.

23. ~~**QCOW2 encryption**~~ — **Done (Phase 16b).** Legacy
    AES-128-CBC decryption (crypt_method=1) is supported via
    `--qcow2-password`. Per-sector CBC with PLAIN64 IV using
    virtual sector numbers. LUKS-in-QCOW2 (crypt_method=2)
    is not yet supported.

24. ~~**QCOW2 snapshots**~~ — **Done (Phase 16c).** Snapshot
    table parsing, detection (info reports count), and extraction
    via `convert --snapshot <ID|name>` are implemented. Up to 16
    snapshots are parsed. Extraction works by overriding the
    active L1 table with the snapshot's L1 table.

## Verification

After each sub-phase:
1. `pre-commit run --all-files` (formatting/clippy)
2. `make imago` (build)
3. `scripts/check-binary-sizes.sh` (384KB limit)
4. `cd tests && ../.venv/bin/stestr run <pattern>` (relevant tests)
5. Full suite: `cd tests && ../.venv/bin/stestr run`
