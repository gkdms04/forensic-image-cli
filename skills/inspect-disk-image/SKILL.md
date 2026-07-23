---
name: inspect-disk-image
description: Inspect forensic disk images without mounting or modifying them. Use for E01/EWF segment sets, VMDK, RAW/DD/IMG, MBR, or GPT images when the agent needs to show partitions, list or regex-search internal paths, read file timestamps, build a timeline, list deleted files, or extract one requested file from NTFS, ext2/3/4, FAT/exFAT, or ISO 9660.
license: MIT
---

# Inspect Disk Image

Use the bundled launcher, which installs or invokes the native `fimg` release for
the host platform:

```console
python scripts/fimg.py --install
python scripts/fimg.py info IMAGE
python scripts/fimg.py partitions IMAGE
python scripts/fimg.py tree IMAGE --max-depth 5
python scripts/fimg.py find IMAGE "(?i)[.](docx|pdf)$"
python scripts/fimg.py stat IMAGE /internal/path
python scripts/fimg.py timeline IMAGE --bodyfile
python scripts/fimg.py deleted IMAGE --partition 2
python scripts/fimg.py extract IMAGE /internal/path --partition 2 --output DEST
```

Pass `--json` to any command for structured output that is easier to parse than
the default text. Supported filesystems: NTFS, ext2/3/4, FAT/exFAT, ISO 9660.

Run `--install` only when the launcher reports that `fimg` is missing. It
downloads the latest Windows or Linux x86-64 release to the user's local data
directory.

## Evidence handling

- Never alter, rename, consolidate, or mount the source image read-write.
- Pass the first `.E01` or `.Ex01` file for a segmented EWF set.
- Pass the descriptor `.vmdk` when a VMDK uses separate extent files.
- Use `partitions` before extraction when multiple filesystems are present.
- A `deleted` result with an empty name is a recovered orphan; report its inode,
  size, and allocation status. Deleted-file coverage varies by filesystem.
- Never add `--overwrite` unless replacing the exact destination is intended.
- Report the selected partition, output path, byte size, and SHA-256 printed by
  the tool.
- Treat results as triage. Recommend independent verification for material
  forensic conclusions.

Skip unsupported or unreadable partitions when scanning all partitions, but
surface the error when the user explicitly selected that partition.

