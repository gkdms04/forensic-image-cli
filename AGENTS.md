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

The `image-formats` CI job builds the same ext4 fixture, converts it to VMDK
(`qemu-img`) and E01 (`ewfacquire`), and runs `tree`/`find`/`extract` against
all three. Reproduce that loop locally when touching container or filesystem
code — it is the only end-to-end coverage.

## Architecture

Three layers, each in one file under `src/`, composed by `main.rs`:

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
   at 16*2048+1) rather than trusting the partition type byte.
   `open_partition_filesystem` returns a `forensic_vfs::DynFs` (`Arc<dyn
   FileSystem>`), which is the unifying abstraction: `ntfs_core::NtfsFs`,
   `ext4fs::Ext4Fs`, and `iso9660_forensic::vfs::IsoVfs` all implement it, so
   `walk_filesystem`, `try_resolve_path`, and `copy_file` are filesystem-
   agnostic. Adding a filesystem = add a `FileSystemKind` variant, a magic check,
   and one `Arc::new(...)` arm.

Note: the `ext4fs-core` package in `Cargo.toml` is imported as `ext4fs`, and
`vmdk-core` is aliased to `vmdk`.

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
downloads the latest GitHub release asset. The `REPOSITORY` constant and the
asset names must stay in sync with `.github/workflows/release.yml`. `SKILL.md`
encodes the evidence-handling rules above for the agent; update it whenever CLI
flags or guarantees change.
