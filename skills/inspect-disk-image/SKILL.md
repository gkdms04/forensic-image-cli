---
name: inspect-disk-image
description: Triage and solve authorized forensic disk-image or CTF challenges without mounting or modifying evidence. Use for E01/EWF sets, VMDK, RAW/DD/IMG, partitions, hidden or deleted evidence, content/flag hunting, timelines, hashing, carving candidates, and extraction from NTFS, ext2/3/4, FAT/exFAT, or ISO 9660.
license: MIT
---

# Inspect Disk Image

Use `python scripts/fimg.py`; run `--install` only if it reports that `fimg` is
missing. Prefer `--json` for agent reasoning and `--progress` for long scans.

## Fast route

Start an open-ended challenge with one bounded inventory:

```console
python scripts/fimg.py triage IMAGE --json --progress
```

Use its ranked findings instead of dumping a full tree. Follow only relevant
branches:

- Suspicious path or signature mismatch: run `stat`, then `extract` and `hash`.
- Recoverable deletion: run `deleted`, then `recover --inode N` to a new path.
- Known flag/question pattern: run `hunt IMAGE PATTERN --scope files --json`.
- No allocated-file hit or unsupported/encrypted filesystem: retry `hunt` with
  `--scope raw`, then use `carve` and `raw-extract` around supported offsets.
- Time-based question: run `timeline --json`; timestamps retain nanoseconds.

Do not run both file and raw hunts before the cheaper file hunt is exhausted.
Keep the default result bounds; raise them only when truncation is reported.
Read [references/ctf-workflow.md](references/ctf-workflow.md) for challenge
routing, command details, and evidence-reporting requirements.

## Evidence handling

- Never alter, rename, consolidate, decrypt in place, or mount source evidence
  read-write. Pass the first `.E01`/`.Ex01` segment and a VMDK descriptor.
- `extract`, `recover`, and `raw-extract` write only to an explicit destination.
  Do not pass `--overwrite` unless replacing that exact output is intended.
- Treat a header reported by `carve` as a candidate, not a proven complete file;
  establish the length before `raw-extract`.
- Report image path and hash scope (`container`, decoded virtual image, or
  internal file), partition, internal path or byte range, size, and hashes.
- Distinguish observed facts from inferences and independently verify material
  conclusions. Respect the competition or investigation's tool-use rules.

