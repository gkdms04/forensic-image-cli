# forensic-image-cli

`fimg` is a native Windows and Linux, read-only CLI for inspecting forensic
disk images without mounting them. It is designed for quick terminal workflows:
show the partition layout, print a file tree, search paths with a regular
expression, and extract a selected file.

Input support:

- E01/EWF v1 and v2, including segmented images
- VMware VMDK, including descriptor/extent and sparse images
- RAW/DD/IMG

Disk and filesystem support:

- MBR and GPT partition tables
- NTFS
- ext2/ext3/ext4
- ISO 9660

exFAT, FAT, HFS+, and APFS are roadmap formats.

## Install

Download the native binary for your platform from GitHub Releases:

- Windows: `fimg-windows-x86_64.exe`
- Linux: `fimg-linux-x86_64`

The binary is self-contained. It does not require WSL, Python, Sleuth Kit,
qemu-img, Dokan, FUSE, or a filesystem mount.

## Agent skill

`fimg` is also packaged as an agent skill (`inspect-disk-image`) for use with
Claude Code, Codex, Cursor, and other agents. Install it with the
[skills.sh](https://skills.sh) CLI:

```console
npx skills add gkdms04/forensic-image-cli
```

The skill's launcher fetches the native binary from GitHub Releases on first
use, so no Rust toolchain is required.

## CLI

```console
fimg info <IMAGE>
fimg partitions <IMAGE>
fimg tree <IMAGE> [--partition N] [--max-depth N]
fimg find <IMAGE> <PATTERN> [--partition N]
fimg extract <IMAGE> <PATH> --output <DEST> [--partition N]
```

Examples:

```console
fimg tree evidence.E01 --max-depth 5
fimg find server.vmdk '(?i)\.(docx|pdf)$'
fimg extract evidence.E01 /Users/Alice/report.docx \
  --partition 3 --output ./report.docx
```

The source image is always opened read-only. `extract` is the only command that
writes evidence-derived data, and it refuses to replace an existing destination
unless `--overwrite` is supplied. Successful extraction prints the output
SHA-256.

## Build

Install a current stable Rust toolchain, then:

```sh
cargo build --release
```

The resulting executable is `target/release/fimg` (`fimg.exe` on Windows).

## Current limits

- Encrypted filesystems and encrypted EWF2 images are rejected.
- FAT/exFAT, HFS+, APFS, BitLocker, LUKS, deleted-file recovery, and alternate
  data streams are not implemented yet.
- Treat this as a triage/extraction helper. Verify important forensic results
  with an independent tool.
