# AGENTS.md

This file provides guidance to coding agents (Claude Code, Codex, and others) when working with code in this repository.

## Project

`fimg` — a single self-contained Rust binary that browses forensic disk images
(E01/EWF, VMDK, RAW/DD) read-only, without mounting, WSL, Sleuth Kit, qemu-img,
FUSE, or Dokan. Ships as `fimg-linux-x86_64` / `fimg-windows-x86_64.exe` via
GitHub Releases; all format decoding comes from pure-Rust crates so no C
toolchain or runtime dependency is introduced. Keep it that way — adding a
dependency with a native/system requirement breaks the distribution model.

Rust edition 2024, MSRV 1.88 (`rust-version` in `Cargo.toml`).

## Commands

```sh
cargo build                      # debug binary at target/debug/fimg
cargo build --release            # release binary at target/release/fimg
cargo fmt --check                # CI gate
cargo clippy --all-targets -- -D warnings   # CI gate; warnings are errors
cargo test --all-targets         # CI gate
cargo test partition::           # run one module's tests
cargo test reads_valid_mbr_primary_partition -- --nocapture
```

Unit tests live in `#[cfg(test)] mod tests` inside each source file; there is no
`tests/` directory and no fixture images are committed.

`filesystem.rs::reads_external_ext4_fixture_when_configured` is a real-image
test that silently skips unless `FIMG_TEST_IMAGE` is set. To exercise it:

```sh
truncate -s 32M /tmp/fimg.raw && mkfs.ext4 -q /tmp/fimg.raw
debugfs -w -R "mkdir /docs" /tmp/fimg.raw
debugfs -w -R "write README.md /docs/README.md" /tmp/fimg.raw
FIMG_TEST_IMAGE=/tmp/fimg.raw FIMG_TEST_PATH=/docs/README.md \
  FIMG_TEST_EXPECTED_FILE=README.md cargo test
```

`filesystem.rs::recovers_deleted_node_from_ntfs_fixture_when_configured` is the
sibling real-image test for NTFS deleted-node recovery (the `deleted` surface
that NTFS exposes with names, unlike ext4). It skips unless
`FIMG_TEST_NTFS_IMAGE` is set. Build a fixture with `ntfs-3g` (mkntfs +
mount-populate-delete) — needs FUSE:

```sh
truncate -s 48M /tmp/fimg-ntfs.raw && mkntfs -Q -F -L NTFS_EVIDENCE /tmp/fimg-ntfs.raw
mkdir -p /tmp/ntfsmnt && ntfs-3g /tmp/fimg-ntfs.raw /tmp/ntfsmnt
mkdir /tmp/ntfsmnt/docs && echo secret > /tmp/ntfsmnt/docs/secret_evidence.txt
sync && rm /tmp/ntfsmnt/docs/secret_evidence.txt && sync
fusermount -u /tmp/ntfsmnt
FIMG_TEST_NTFS_IMAGE=/tmp/fimg-ntfs.raw \
  FIMG_TEST_DELETED_NAME=secret_evidence.txt cargo test
```

The `image-formats` CI job builds an ext4 fixture, converts it to VMDK
(`qemu-img`) and E01 (`ewfacquire`), and also builds FAT32 and NTFS (with a
deleted file) fixtures, plus a best-effort exFAT fixture (skipped when the runner
kernel lacks exFAT). It runs `tree`/`find`/`stat`/`timeline`/`info
--json`/`extract` against every container and filesystem, plus `deleted` against
the NTFS image. Reproduce that loop locally when touching container or filesystem
code — it is the only end-to-end coverage.

## Architecture

Three layers under `src/`, composed by `main.rs`; `output.rs` renders results:

1. **`image.rs` — container layer.** `ImageFactory::detect` sniffs the first 512
   bytes plus the file extension to pick `Raw` / `Ewf` / `Vmdk`, then
   `ImageFactory::open()` returns a `Box<dyn ReadSeek>` presenting the *virtual*
   (decoded) byte stream. Virtual size is discovered by seeking to the end.
   `WindowReader<R>` clamps an underlying reader to `[base, base+len)` and
   re-seeks the inner reader on every `read` — this is what turns a whole-disk
   stream into a per-partition stream.

2. **`partition.rs` — disk layout.** `read_partitions` requires an MBR
   signature, tries GPT first at both 512- and 4096-byte sector sizes, falls back
   to MBR primaries, and finally to a synthetic `Whole` partition (`number: 0`)
   covering the entire image so unpartitioned filesystem images still work.
   Bounds and entry-count/size limits are enforced against the image length;
   malformed tables `bail!` rather than producing out-of-range partitions.

3. **`filesystem.rs` — filesystem layer.** `detect_filesystem` reads magics
   directly (NTFS OEM at 0x03, ext superblock magic at 1024+56, ISO 9660 `CD001`
   at 16*2048+1, FAT/exFAT via the 0x55AA boot signature plus the exFAT OEM name
   or FAT type label) rather than trusting the partition type byte.
   `open_partition_filesystem` returns a `forensic_vfs::DynFs` (`Arc<dyn
   FileSystem>`), which is the unifying abstraction: `ntfs_core::NtfsFs`,
   `ext4fs::Ext4Fs`, `fatfs::FatFs`, and `iso9660_forensic::vfs::IsoVfs` all
   implement it, so `walk_filesystem`, `try_resolve_path`, `copy_file`, and
   `list_deleted` are filesystem-agnostic. Adding a filesystem = add a
   `FileSystemKind` variant, a magic check, and one `Arc::new(...)` arm.

4. **`output.rs` — rendering.** `OutputFormat` (from the global `--json` flag)
   and the serializable report DTOs. Each `command_*` builds a DTO and branches
   Text vs `print_json`. Timestamps come from `forensic_vfs::TimeStamp.unix_nanos`
   (`i128`, no `Display`); `format_ts` renders RFC 3339 UTC via an inline
   civil-date helper — **no calendar/time dependency**. `None` times stay `null`
   (not epoch zero). `list_deleted` merges the rich `deleted_nodes()` (NTFS:
   name + id) and bare `deleted()` (ext/FAT/ISO: `FsMeta`) surfaces, deduped by
   inode.

Note: `Cargo.toml` aliases `ext4fs-core` → `ext4fs`, `vmdk-core` → `vmdk`, and
`fat-core` → `fatfs` (its own lib name is the too-generic `fat`).

**Reopen-per-operation:** `detect_partition_filesystem` and
`open_partition_filesystem` each call `factory.open()` afresh instead of sharing
one reader. `DynFs` instances own their reader, so each partition needs its own.
Commands that scan all partitions therefore reopen the container repeatedly —
correct but not cheap on large E01 sets.

## Invariants

These are product guarantees, not style preferences — do not relax them:

- The source image is opened read-only and never written, renamed, or mounted.
- `extract` is the only command that writes. It writes to a `NamedTempFile` in
  the destination directory, `sync_all()`s, then `persist()`s — never a partial
  file at the destination. It refuses an existing destination unless
  `--overwrite`, refuses directories, and refuses non-regular-file nodes.
- Every successful extraction prints the SHA-256 computed *during* the copy in
  `copy_file`, plus image path, partition, internal path, and size.
- `try_resolve_path` normalizes `\` to `/` and rejects `..` components outright.
- Traversal is bounded: `MAX_WALK_DEPTH` 256, `MAX_DIRECTORY_ENTRIES` 1,000,000,
  and a `visited: HashSet<FileId>` guards against directory cycles.
- Multi-partition behavior: when the user did *not* pass `--partition`,
  unsupported filesystems are skipped (with a warning for `tree`); when they
  *did*, the unsupported filesystem is a hard error. `extract` refuses when the
  path resolves in more than one partition and demands `--partition`.
- Errors are `anyhow` with `.context()`/`with_context()` naming the image,
  partition (`p{n}`), or path involved; user-facing failures use `bail!`.

## skills/

`skills/inspect-disk-image/` packages the CLI as an agent skill. It sits at the
standard `skills/<name>/SKILL.md` catalog path so the skills.sh CLI (`npx skills
add gkdms04/forensic-image-cli`) and Codex both discover it; `agents/openai.yaml`
carries the Codex-specific interface metadata. `scripts/fimg.py` locates `fimg`
via `$FIMG_BIN`, `PATH`, then the per-user install dir, and `--install`
downloads the latest GitHub release asset **and verifies it against the release
`SHA256SUMS` before installing** — never relax that check. The `REPOSITORY`
constant, the per-platform asset names in `asset_name()`, and the release matrix
in `.github/workflows/release.yml` must stay in sync (Windows x86-64, Linux
x86-64/arm64, macOS x86-64/arm64). `SKILL.md` encodes the evidence-handling
rules above for the agent; update it whenever CLI flags or guarantees change.
