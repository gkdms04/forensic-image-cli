use std::collections::HashSet;
use std::io::{Read, Seek, SeekFrom};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use forensic_vfs::{Allocation, DynFs, FileId, FileSystem, FsMeta, MacbTimes, NodeKind, StreamId};
use sha2::{Digest, Sha256};

use crate::image::{ImageFactory, WindowReader};
use crate::partition::Partition;

const MAX_WALK_DEPTH: usize = 256;
const MAX_DIRECTORY_ENTRIES: usize = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileSystemKind {
    Ntfs,
    Ext,
    Fat,
    Iso9660,
    Unknown,
}

impl std::fmt::Display for FileSystemKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ntfs => formatter.write_str("NTFS"),
            Self::Ext => formatter.write_str("ext2/3/4"),
            Self::Fat => formatter.write_str("FAT/exFAT"),
            Self::Iso9660 => formatter.write_str("ISO 9660"),
            Self::Unknown => formatter.write_str("unknown"),
        }
    }
}

/// A deleted or orphaned node recovered from a filesystem, merged from the
/// bare-[`FsMeta`] and rich [`forensic_vfs::DeletedNode`] surfaces.
#[derive(Debug, Clone)]
pub struct DeletedEntry {
    pub ino: u64,
    pub name: Option<String>,
    pub kind: NodeKind,
    pub allocated: Allocation,
    pub size: u64,
    pub times: MacbTimes,
}

#[derive(Debug, Clone)]
pub struct WalkEntry {
    pub id: FileId,
    pub ino: u64,
    pub path: String,
    pub name: String,
    pub depth: usize,
    pub kind: NodeKind,
    pub size: u64,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub mode: Option<u32>,
    pub times: MacbTimes,
    pub is_last: bool,
    pub ancestor_is_last: Vec<bool>,
}

pub fn detect_partition_filesystem(
    factory: &ImageFactory,
    partition: &Partition,
) -> Result<FileSystemKind> {
    let opened = factory.open()?;
    let mut reader =
        WindowReader::new(opened.reader, partition.byte_offset(), partition.byte_len());
    detect_filesystem(&mut reader)
}

pub fn open_partition_filesystem(
    factory: &ImageFactory,
    partition: &Partition,
) -> Result<(FileSystemKind, DynFs)> {
    let opened = factory.open()?;
    let mut reader =
        WindowReader::new(opened.reader, partition.byte_offset(), partition.byte_len());
    let kind = detect_filesystem(&mut reader)?;
    reader.seek(SeekFrom::Start(0))?;
    let filesystem: DynFs = match kind {
        FileSystemKind::Ntfs => Arc::new(
            ntfs_core::NtfsFs::open(reader)
                .with_context(|| format!("cannot open NTFS in p{}", partition.number))?,
        ),
        FileSystemKind::Ext => Arc::new(
            ext4fs::Ext4Fs::open(reader)
                .with_context(|| format!("cannot open ext filesystem in p{}", partition.number))?,
        ),
        FileSystemKind::Fat => Arc::new(
            fatfs::FatFs::open(reader)
                .with_context(|| format!("cannot open FAT/exFAT in p{}", partition.number))?,
        ),
        FileSystemKind::Iso9660 => Arc::new(
            iso9660_forensic::vfs::IsoVfs::open(reader)
                .with_context(|| format!("cannot open ISO 9660 in p{}", partition.number))?,
        ),
        FileSystemKind::Unknown => {
            bail!(
                "unsupported or unrecognized filesystem in p{} at byte offset {}",
                partition.number,
                partition.byte_offset()
            )
        }
    };
    Ok((kind, filesystem))
}

pub fn detect_filesystem<R: Read + Seek>(reader: &mut R) -> Result<FileSystemKind> {
    let mut boot = [0_u8; 512];
    reader.seek(SeekFrom::Start(0))?;
    let boot_len = read_up_to(reader, &mut boot)?;
    if boot_len >= 11 && &boot[3..11] == b"NTFS    " {
        return Ok(FileSystemKind::Ntfs);
    }

    let mut ext_magic = [0_u8; 2];
    reader.seek(SeekFrom::Start(1024 + 56))?;
    if reader.read_exact(&mut ext_magic).is_ok() && ext_magic == [0x53, 0xef] {
        return Ok(FileSystemKind::Ext);
    }

    let mut iso_magic = [0_u8; 5];
    reader.seek(SeekFrom::Start(16 * 2048 + 1))?;
    if reader.read_exact(&mut iso_magic).is_ok() && &iso_magic == b"CD001" {
        return Ok(FileSystemKind::Iso9660);
    }

    // FAT/exFAT: gated on the 0x55AA boot signature, then the exFAT OEM name at
    // offset 3 or the FAT filesystem-type label (FAT12/16 at 0x36, FAT32 at
    // 0x52). fat-core's open() performs the authoritative BPB validation.
    if boot_len >= 512 && boot[510] == 0x55 && boot[511] == 0xaa {
        let is_exfat = &boot[3..11] == b"EXFAT   ";
        let fat1x = matches!(&boot[54..62], b"FAT12   " | b"FAT16   " | b"FAT     ");
        let fat32 = &boot[82..90] == b"FAT32   ";
        if is_exfat || fat1x || fat32 {
            return Ok(FileSystemKind::Fat);
        }
    }

    Ok(FileSystemKind::Unknown)
}

fn read_up_to(reader: &mut impl Read, buffer: &mut [u8]) -> std::io::Result<usize> {
    let mut total = 0;
    while total < buffer.len() {
        let read = reader.read(&mut buffer[total..])?;
        if read == 0 {
            break;
        }
        total += read;
    }
    Ok(total)
}

pub fn walk_filesystem(
    filesystem: &dyn FileSystem,
    max_depth: Option<usize>,
    mut visit: impl FnMut(&WalkEntry) -> Result<()>,
) -> Result<()> {
    let limit = max_depth.unwrap_or(MAX_WALK_DEPTH).min(MAX_WALK_DEPTH);
    let root = filesystem.root();
    let mut visited = HashSet::new();
    visited.insert(root);
    walk_directory(
        filesystem,
        root,
        "",
        0,
        limit,
        &mut visited,
        &mut Vec::new(),
        &mut visit,
    )
}

#[allow(clippy::too_many_arguments)]
fn walk_directory(
    filesystem: &dyn FileSystem,
    directory: FileId,
    parent_path: &str,
    depth: usize,
    max_depth: usize,
    visited: &mut HashSet<FileId>,
    ancestor_is_last: &mut Vec<bool>,
    visit: &mut impl FnMut(&WalkEntry) -> Result<()>,
) -> Result<()> {
    if depth >= max_depth {
        return Ok(());
    }
    let mut entries = filesystem
        .read_dir(directory)
        .context("cannot list directory")?
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("cannot read directory entry")?;
    if entries.len() > MAX_DIRECTORY_ENTRIES {
        bail!(
            "directory entry limit exceeded ({MAX_DIRECTORY_ENTRIES}); refusing unbounded traversal"
        );
    }
    entries.retain(|entry| entry.name.as_slice() != b"." && entry.name.as_slice() != b"..");
    entries.sort_by(|left, right| {
        left.name
            .to_ascii_lowercase()
            .cmp(&right.name.to_ascii_lowercase())
    });
    let count = entries.len();

    for (index, entry) in entries.into_iter().enumerate() {
        let is_last = index + 1 == count;
        let name = String::from_utf8_lossy(&entry.name).into_owned();
        let path = if parent_path.is_empty() {
            format!("/{name}")
        } else {
            format!("{parent_path}/{name}")
        };
        let meta = filesystem
            .meta(entry.id)
            .with_context(|| format!("cannot read metadata for '{path}'"))?;
        let record = WalkEntry {
            id: entry.id,
            ino: meta.ino,
            path: path.clone(),
            name,
            depth: depth + 1,
            kind: entry.kind,
            size: meta.size,
            uid: meta.uid,
            gid: meta.gid,
            mode: meta.mode,
            times: meta.times,
            is_last,
            ancestor_is_last: ancestor_is_last.clone(),
        };
        visit(&record)?;

        if entry.kind == NodeKind::Dir && depth + 1 < max_depth && visited.insert(entry.id) {
            ancestor_is_last.push(is_last);
            walk_directory(
                filesystem,
                entry.id,
                &path,
                depth + 1,
                max_depth,
                visited,
                ancestor_is_last,
                visit,
            )?;
            ancestor_is_last.pop();
        }
    }
    Ok(())
}

pub fn resolve_path(filesystem: &dyn FileSystem, internal_path: &str) -> Result<(FileId, FsMeta)> {
    try_resolve_path(filesystem, internal_path)?
        .with_context(|| format!("path not found: '{internal_path}'"))
}

pub fn try_resolve_path(
    filesystem: &dyn FileSystem,
    internal_path: &str,
) -> Result<Option<(FileId, FsMeta)>> {
    let mut current = filesystem.root();
    let normalized = internal_path.replace('\\', "/");
    for component in normalized
        .split('/')
        .filter(|component| !component.is_empty())
    {
        if component == "." {
            continue;
        }
        if component == ".." {
            bail!("parent path components are not allowed: '{internal_path}'");
        }
        let Some(next) = filesystem
            .lookup(current, component.as_bytes())
            .with_context(|| format!("cannot look up '{component}'"))?
        else {
            return Ok(None);
        };
        current = next;
    }
    let meta = filesystem
        .meta(current)
        .with_context(|| format!("cannot read metadata for '{internal_path}'"))?;
    Ok(Some((current, meta)))
}

pub fn copy_file(
    filesystem: &dyn FileSystem,
    id: FileId,
    size: u64,
    mut output: impl std::io::Write,
) -> Result<[u8; 32]> {
    const BUFFER_SIZE: usize = 1024 * 1024;
    let mut offset = 0_u64;
    let mut buffer = vec![0_u8; BUFFER_SIZE];
    let mut digest = Sha256::new();
    while offset < size {
        let wanted = (size - offset).min(BUFFER_SIZE as u64) as usize;
        let read = filesystem
            .read_at(id, StreamId::Default, offset, &mut buffer[..wanted])
            .with_context(|| format!("cannot read file at byte offset {offset}"))?;
        if read == 0 {
            bail!("unexpected end of file at byte offset {offset} of {size}");
        }
        output.write_all(&buffer[..read])?;
        digest.update(&buffer[..read]);
        offset += read as u64;
    }
    Ok(digest.finalize().into())
}

/// Enumerate deleted and orphaned nodes, merging the rich
/// [`FileSystem::deleted_nodes`] surface (identity + recovered name, e.g. NTFS)
/// with the bare [`FileSystem::deleted`] surface (ext/ISO/FAT), deduplicated by
/// metadata address. The traversal is bounded like directory walks.
pub fn list_deleted(filesystem: &dyn FileSystem) -> Result<Vec<DeletedEntry>> {
    let mut entries = Vec::new();
    let mut seen = HashSet::new();

    for node in filesystem
        .deleted_nodes()
        .context("cannot enumerate deleted nodes")?
    {
        let node = node.context("cannot read deleted node")?;
        if !seen.insert(node.meta.ino) {
            continue;
        }
        let name =
            (!node.name.is_empty()).then(|| String::from_utf8_lossy(&node.name).into_owned());
        entries.push(DeletedEntry {
            ino: node.meta.ino,
            name,
            kind: node.meta.kind,
            allocated: node.meta.allocated,
            size: node.meta.size,
            times: node.meta.times,
        });
        if entries.len() > MAX_DIRECTORY_ENTRIES {
            bail!("deleted-node limit exceeded ({MAX_DIRECTORY_ENTRIES})");
        }
    }

    for meta in filesystem
        .deleted()
        .context("cannot enumerate deleted metadata")?
    {
        let meta = meta.context("cannot read deleted metadata")?;
        if !seen.insert(meta.ino) {
            continue;
        }
        entries.push(DeletedEntry {
            ino: meta.ino,
            name: None,
            kind: meta.kind,
            allocated: meta.allocated,
            size: meta.size,
            times: meta.times,
        });
        if entries.len() > MAX_DIRECTORY_ENTRIES {
            bail!("deleted-node limit exceeded ({MAX_DIRECTORY_ENTRIES})");
        }
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use forensic_vfs::{
        Allocation, DirEntry, DirStream, ExtentStream, FileId, FileSystem, FsKind, FsMeta,
        MacbTimes, NodeKind, NodeStream, ResidencyKind, SectorSizes, StreamId, TimeZonePolicy,
        VfsResult,
    };

    use super::{FileSystemKind, detect_filesystem, resolve_path, walk_filesystem};

    #[test]
    fn detects_exfat_by_oem_signature() {
        let mut boot = vec![0_u8; 512];
        boot[3..11].copy_from_slice(b"EXFAT   ");
        boot[510] = 0x55;
        boot[511] = 0xaa;
        assert_eq!(
            detect_filesystem(&mut std::io::Cursor::new(boot)).unwrap(),
            FileSystemKind::Fat
        );
    }

    #[test]
    fn detects_fat32_by_type_label() {
        let mut boot = vec![0_u8; 512];
        boot[82..90].copy_from_slice(b"FAT32   ");
        boot[510] = 0x55;
        boot[511] = 0xaa;
        assert_eq!(
            detect_filesystem(&mut std::io::Cursor::new(boot)).unwrap(),
            FileSystemKind::Fat
        );
    }

    #[test]
    fn detects_fat16_by_type_label() {
        let mut boot = vec![0_u8; 512];
        boot[54..62].copy_from_slice(b"FAT16   ");
        boot[510] = 0x55;
        boot[511] = 0xaa;
        assert_eq!(
            detect_filesystem(&mut std::io::Cursor::new(boot)).unwrap(),
            FileSystemKind::Fat
        );
    }

    #[test]
    fn unsigned_boot_sector_is_not_fat() {
        let mut boot = vec![0_u8; 512];
        boot[82..90].copy_from_slice(b"FAT32   "); // label present, signature absent
        assert_eq!(
            detect_filesystem(&mut std::io::Cursor::new(boot)).unwrap(),
            FileSystemKind::Unknown
        );
    }

    struct MockFs {
        dirs: HashMap<FileId, Vec<DirEntry>>,
        files: HashMap<FileId, Vec<u8>>,
    }

    impl MockFs {
        fn fixture() -> Self {
            let root = FileId::Opaque(1);
            let users = FileId::Opaque(2);
            let report = FileId::Opaque(3);
            Self {
                dirs: HashMap::from([
                    (
                        root,
                        vec![DirEntry {
                            name: b"Users".to_vec(),
                            id: users,
                            kind: NodeKind::Dir,
                        }],
                    ),
                    (
                        users,
                        vec![DirEntry {
                            name: b"report.txt".to_vec(),
                            id: report,
                            kind: NodeKind::File,
                        }],
                    ),
                ]),
                files: HashMap::from([(report, b"evidence".to_vec())]),
            }
        }
    }

    impl FileSystem for MockFs {
        fn kind(&self) -> FsKind {
            FsKind::from_name("mock")
        }

        fn root(&self) -> FileId {
            FileId::Opaque(1)
        }

        fn sector_sizes(&self) -> SectorSizes {
            SectorSizes {
                logical: 512,
                physical: 512,
                cluster_or_block: 4096,
            }
        }

        fn timestamp_zone(&self) -> TimeZonePolicy {
            TimeZonePolicy::Utc
        }

        fn read_dir(&self, ino: FileId) -> VfsResult<DirStream> {
            let entries = self.dirs.get(&ino).cloned().unwrap_or_default();
            Ok(DirStream::new(entries.into_iter().map(Ok)))
        }

        fn extents(&self, _ino: FileId, _stream: StreamId) -> VfsResult<ExtentStream> {
            Ok(ExtentStream::empty())
        }

        fn lookup(&self, parent: FileId, name: &[u8]) -> VfsResult<Option<FileId>> {
            Ok(self
                .dirs
                .get(&parent)
                .and_then(|entries| entries.iter().find(|entry| entry.name == name))
                .map(|entry| entry.id))
        }

        fn meta(&self, ino: FileId) -> VfsResult<FsMeta> {
            let is_dir = self.dirs.contains_key(&ino);
            Ok(FsMeta {
                ino: match ino {
                    FileId::Opaque(value) => value,
                    _ => 0,
                },
                kind: if is_dir {
                    NodeKind::Dir
                } else {
                    NodeKind::File
                },
                allocated: Allocation::Allocated,
                size: self.files.get(&ino).map_or(0, |bytes| bytes.len() as u64),
                nlink: 1,
                uid: None,
                gid: None,
                mode: None,
                times: MacbTimes::default(),
                streams: Vec::new(),
                residency: ResidencyKind::NonResident,
                link_target: None,
            })
        }

        fn read_at(
            &self,
            ino: FileId,
            _stream: StreamId,
            off: u64,
            buffer: &mut [u8],
        ) -> VfsResult<usize> {
            let bytes = self.files.get(&ino).map(Vec::as_slice).unwrap_or_default();
            let start = (off as usize).min(bytes.len());
            let count = buffer.len().min(bytes.len() - start);
            buffer[..count].copy_from_slice(&bytes[start..start + count]);
            Ok(count)
        }

        fn read_link(&self, _ino: FileId, _cap: usize) -> VfsResult<Vec<u8>> {
            Ok(Vec::new())
        }

        fn deleted(&self) -> VfsResult<NodeStream> {
            Ok(NodeStream::empty())
        }

        fn unallocated(&self) -> VfsResult<ExtentStream> {
            Ok(ExtentStream::empty())
        }
    }

    #[test]
    fn walks_nested_paths_in_tree_order() {
        let filesystem = MockFs::fixture();
        let mut paths = Vec::new();
        walk_filesystem(&filesystem, None, |entry| {
            paths.push(entry.path.clone());
            Ok(())
        })
        .unwrap();
        assert_eq!(paths, vec!["/Users", "/Users/report.txt"]);
    }

    #[test]
    fn resolves_slashes_and_rejects_parent_escape() {
        let filesystem = MockFs::fixture();
        let (id, meta) = resolve_path(&filesystem, r"\Users\report.txt").unwrap();
        assert_eq!(id, FileId::Opaque(3));
        assert_eq!(meta.size, 8);
        assert!(resolve_path(&filesystem, "/Users/../report.txt").is_err());
    }

    #[test]
    fn reads_external_ext4_fixture_when_configured() {
        use crate::image::ImageFactory;
        use crate::partition::read_partitions;

        let Some(image) = std::env::var_os("FIMG_TEST_IMAGE") else {
            eprintln!("FIMG_TEST_IMAGE is not set; skipping external fixture");
            return;
        };
        let expected_path =
            std::env::var("FIMG_TEST_PATH").unwrap_or_else(|_| "/docs/README.md".into());
        let factory = ImageFactory::detect(image).unwrap();
        let mut opened = factory.open().unwrap();
        let partitions = read_partitions(&mut opened.reader, opened.virtual_size).unwrap();
        let partition = partitions.first().unwrap();
        let (kind, filesystem) = super::open_partition_filesystem(&factory, partition).unwrap();
        assert_eq!(kind, super::FileSystemKind::Ext);

        let (id, meta) = super::resolve_path(filesystem.as_ref(), &expected_path).unwrap();
        let mut extracted = Vec::new();
        super::copy_file(filesystem.as_ref(), id, meta.size, &mut extracted).unwrap();
        assert!(!extracted.is_empty());
        if let Ok(expected_file) = std::env::var("FIMG_TEST_EXPECTED_FILE") {
            assert_eq!(extracted, std::fs::read(expected_file).unwrap());
        }
    }
}
