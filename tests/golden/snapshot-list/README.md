# snapshot-list JSON goldens

One file per baselined snapshot fixture. These are instar-side
self-baselines: `qemu-img snapshot -l` has no `--output=json`
equivalent, so there is no qemu source of truth. The goldens
freeze the instar QMP-schema JSON output; the structural
cross-check test in `test_snapshot.py` keeps them honest.

## Regeneration

```
INSTAR=src/target/release/instar
SNAPDIR=/path/to/instar-testdata/custom/snapshots
GOLD=tests/golden/snapshot-list
for img in snap-qcow2-512 snap-qcow2-backing-base snap-qcow2-backing \
           snap-qcow2-dupname snap-qcow2-extl2 snap-qcow2-longname \
           snap-qcow2-namecollision snap-qcow2-v2 snap-qcow2-v3-one \
           snap-qcow2-v3-sixteen snap-qcow2-v3-two snap-qcow2-vmstate; do
  TZ=UTC $INSTAR snapshot -l --output=json "$SNAPDIR/${img}.qcow2" \
    > "$GOLD/${img}.json"
done
```

Regenerate any time the JSON schema changes or the fixture changes.
After regenerating, re-run the structural cross-check:

```
stestr run test_snapshot.TestSnapshotListGoldens
```
