# forensic-image-cli

`fimg` is a cross-platform, read-only CLI for inspecting forensic disk images
without mounting them. It is designed for quick terminal workflows: show the
partition layout, print a file tree, search paths with a regular expression,
and extract a selected file.

Planned input support:

- E01/EWF, including segmented images
- VMware VMDK
- RAW/DD/IMG

Initial filesystem support:

- NTFS
- ext2/ext3/ext4
- ISO 9660

exFAT, FAT, HFS+, and APFS are roadmap formats.

## CLI

```text
fimg info <IMAGE>
fimg partitions <IMAGE>
fimg tree <IMAGE> [--partition N] [--max-depth N]
fimg find <IMAGE> <PATTERN> [--partition N]
fimg extract <IMAGE> <PATH> --output <DEST> [--partition N]
```

The source image is always opened read-only. `extract` is the only command that
writes evidence-derived data, and it refuses to replace an existing destination
unless `--overwrite` is supplied.

## Build

Install a current stable Rust toolchain, then:

```sh
cargo build --release
```

The resulting executable is `target/release/fimg` (`fimg.exe` on Windows).
