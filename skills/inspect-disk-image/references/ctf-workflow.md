# CTF disk-image workflow

## Commands

```console
python scripts/fimg.py triage IMAGE --json --progress
python scripts/fimg.py info IMAGE --json
python scripts/fimg.py partitions IMAGE --json
python scripts/fimg.py tree IMAGE --partition N --max-depth 5
python scripts/fimg.py find IMAGE '(?i)[.](pdf|docx|zip)$' --json
python scripts/fimg.py hunt IMAGE 'DFC\{[^}]+\}' --scope files --json --progress
python scripts/fimg.py hunt IMAGE 'password|secret|recovery[ _-]?key' --scope raw -i --json
python scripts/fimg.py stat IMAGE /internal/path --partition N --json
python scripts/fimg.py hash IMAGE /internal/path --partition N --json
python scripts/fimg.py hash IMAGE --container --json
python scripts/fimg.py timeline IMAGE --partition N --json --progress
python scripts/fimg.py deleted IMAGE --partition N --json
python scripts/fimg.py recover IMAGE --inode 42 --partition N --output DEST
python scripts/fimg.py carve IMAGE --type pdf --json
python scripts/fimg.py raw-extract IMAGE --offset 0x12000 --length 4096 --output DEST
python scripts/fimg.py extract IMAGE /internal/path --partition N --output DEST
```

`hash IMAGE` hashes decoded virtual media; `--container` hashes the exact file
passed to the command. For segmented EWF, a container hash covers only that
segment, not the set. `hunt` scans ASCII/UTF-8 and UTF-16LE. Its offsets are
relative to an internal file for `source=file` and to decoded virtual media for
`source=raw`.

## Routing

1. Preserve the question's exact requested value, time zone, hash algorithm,
   flag syntax, and output form. Use that syntax as the narrowest hunt regex.
2. Run `triage --json`. Inspect high-severity findings, deleted counts,
   encryption detection, and truncation before expanding the search.
3. Search filenames with `find` only when the question points to a file type or
   name. Search content with `hunt`; allocated files are faster and attribute a
   match to a path, while raw scanning covers slack and unallocated data.
4. Use `stat` for inode/MFT identity and nanosecond MACB times. Use `timeline`
   for ordering or anomaly comparison; do not round timestamps before analysis.
5. Use `deleted` before `recover`. Only entries with a readable identity can be
   recovered; recovered clusters may be partly overwritten.
6. Use `carve` after filesystem-aware methods. It finds headers but intentionally
   does not guess ends. Confirm structure/footer or obtain a question-supplied
   size before `raw-extract`.
7. Hash every extracted result and retain commands, offsets, paths, and tool
   output needed to reproduce the answer.

## Unsupported and encrypted volumes

BitLocker and LUKS headers are detected but not decrypted. Search authorized
companion artifacts for keys, record the matched key identifier, and use an
independent read-only decryptor. XFS, APFS, and HFS+ are not parsed; use raw
`hunt`/`carve` for quick leads and disclose that filesystem metadata was not
interpreted.

