# forensic-image-cli

`fimg` is a native Windows, Linux, and macOS, read-only CLI for inspecting
forensic disk images without mounting them. It is designed for quick terminal
workflows: run CTF-oriented triage, hunt file or raw content, locate embedded
file signatures, inspect the partition layout and timeline, recover deleted
files, and extract selected files or exact byte ranges. Every command can emit
JSON with `--json`.

Input support:

- E01/EWF v1 and v2, including segmented images
- VMware VMDK, including descriptor/extent and sparse images
- RAW/DD/IMG

Disk and filesystem support:

- MBR and GPT partition tables
- NTFS
- ext2/ext3/ext4
- FAT12/16/32 and exFAT
- ISO 9660

HFS+ and APFS are roadmap formats.

## Install

Download the native binary for your platform from GitHub Releases:

- Windows: `fimg-windows-x86_64.exe`
- Linux: `fimg-linux-x86_64`, `fimg-linux-aarch64`
- macOS: `fimg-macos-x86_64`, `fimg-macos-aarch64`

Each release also publishes a `SHA256SUMS` file; verify your download against it.

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
use, verifies it against the release `SHA256SUMS`, and caches it locally, so no
Rust toolchain is required. Prebuilt binaries cover Windows x86-64, Linux
x86-64/arm64, and macOS x86-64/arm64.

## CLI

### CTF quick start

Use the cheapest, most attributable searches first and expand only when needed:

```console
# 1. Inventory partitions, hashes, deleted entries, and ranked anomalies.
fimg triage challenge.E01 --json --progress

# 2. Search allocated files first; matches include their internal paths.
fimg hunt challenge.E01 'DFC\{[^}]+\}' --scope files --json --progress

# 3. If that misses, include slack/unallocated bytes in the virtual image.
fimg hunt challenge.E01 'DFC\{[^}]+\}' --scope raw --json --progress

# 4. Inspect and extract a lead without modifying the image.
fimg stat challenge.E01 /suspicious/path --partition 2 --json
fimg extract challenge.E01 /suspicious/path --partition 2 --output ./artifact.bin
```

For a Codex/agent workflow, attach or name the image and ask it to use
`$inspect-disk-image`. The skill starts with `triage`, consumes JSON, follows
ranked leads, and records paths, offsets, partitions, and hashes for a
reproducible answer. Competition rules still determine whether agent-assisted
analysis is allowed.

### Command reference

| Command | Purpose |
| --- | --- |
| `triage` | Hash and inventory the image, then rank metadata/signature anomalies and deleted evidence. |
| `hunt` | Regex-search allocated files, raw virtual media, or both; includes UTF-16LE. |
| `info`, `partitions` | Identify the container, virtual size, partition layout, and filesystem types. |
| `tree`, `find`, `stat` | Browse paths, regex-search names, and inspect metadata/MAC(B) times. |
| `timeline` | Export timestamped filesystem activity as text, JSON, or a bodyfile. |
| `deleted`, `recover` | List deleted nodes and recover a selected readable node by inode or name. |
| `hash` | Calculate MD5, SHA-1, and SHA-256 for a container, virtual image, or internal file. |
| `carve`, `raw-extract` | Locate known headers, then copy an explicitly selected virtual byte range. |
| `extract` | Copy one allocated internal file to an explicit destination. |

```console
fimg triage <IMAGE> [--partition N] [--no-hash]
fimg info <IMAGE>
fimg partitions <IMAGE>
fimg tree <IMAGE> [--partition N] [--max-depth N]
fimg find <IMAGE> <PATTERN> [--partition N] [--ignore-case]
fimg hunt <IMAGE> [PATTERN] [--scope files|raw|all]
fimg hash <IMAGE> [PATH] [--partition N] [--container]
fimg stat <IMAGE> <PATH> [--partition N]
fimg timeline <IMAGE> [--partition N] [--bodyfile]
fimg deleted <IMAGE> [--partition N]
fimg recover <IMAGE> (--inode N|--name NAME) --output <DEST>
fimg carve <IMAGE> [--type TYPE]
fimg raw-extract <IMAGE> --offset N --length N --output <DEST>
fimg extract <IMAGE> <PATH> --output <DEST> [--partition N]
```

Any command accepts `--json` for machine-readable output.

Examples:

```console
fimg tree evidence.E01 --max-depth 5
fimg find server.vmdk '(?i)\.(docx|pdf)$'
fimg triage evidence.E01 --json --progress
fimg hunt evidence.E01 'DFC\{[^}]+\}' --scope files --json
fimg hunt evidence.E01 'DFC\{[^}]+\}' --scope raw --json
fimg hash evidence.E01 /Users/Alice/report.docx --json
fimg stat evidence.E01 /Users/Alice/report.docx --json
fimg timeline evidence.E01 --bodyfile > bodyfile.txt   # feed Sleuth Kit mactime
fimg deleted evidence.E01 --partition 2
fimg recover evidence.E01 --name secret.txt --partition 2 --output secret.txt
fimg carve evidence.E01 --type pdf --json
fimg raw-extract evidence.E01 --offset 0x12000 --length 4096 --output candidate.bin
fimg extract evidence.E01 /Users/Alice/report.docx \
  --partition 3 --output ./report.docx
```

The source image is always opened read-only. `extract`, `recover`, and
`raw-extract` only write evidence-derived data to an explicit destination. They
refuse to replace an existing destination unless `--overwrite` is supplied and
print hashes for every successful output.

`triage` calculates all three common CTF hashes, inventories supported
filesystems, lists deleted evidence, detects BitLocker/LUKS volumes, and ranks
suspicious paths, file-signature mismatches, hidden names, and timestamp
anomalies. `hunt` searches allocated file content or the decoded virtual media
with a byte regex and automatically performs an ASCII/UTF-8 and UTF-16LE pass.
Both commands bound their result counts for hostile or accidentally broad
inputs. `carve` reports candidate offsets without guessing file lengths;
`raw-extract` copies an operator-selected range using decimal or `0x` offsets.

`stat` and `timeline` surface the MAC(B) timestamps preserved by each
filesystem; a missing time is shown as empty/`null` rather than epoch zero, which
is forensically distinct. `deleted` recovers deleted and orphaned nodes where the
filesystem allows (NTFS reports recovered names; ext/FAT expose bare metadata).

## Build

Install a current stable Rust toolchain, then:

```sh
cargo build --release
```

The resulting executable is `target/release/fimg` (`fimg.exe` on Windows).

## Current limits

- Encrypted filesystems and encrypted EWF2 images are rejected.
- HFS+, APFS, BitLocker/LUKS decryption, XFS, automatic carved-file length
  reconstruction, and alternate data streams are not implemented yet.
  BitLocker and LUKS headers are detected. Deleted-file enumeration depends on
  the filesystem: NTFS recovers names, ext/FAT surface bare metadata, and ISO
  9660 exposes none.
- Treat this as a triage/extraction helper. Verify important forensic results
  with an independent tool.
