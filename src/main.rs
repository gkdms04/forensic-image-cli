use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use forensic_image_cli::digest::{hash_node, hash_reader};
use forensic_image_cli::filesystem::{
    DeletedEntry, FileSystemKind, copy_file, detect_partition_filesystem, list_deleted,
    try_open_partition_filesystem, try_resolve_path, walk_filesystem,
};
use forensic_image_cli::image::ImageFactory;
use forensic_image_cli::output::{
    DeletedRow, ExtractReport, FindMatch, HashReport, InfoPartition, InfoReport, OutputFormat,
    PartitionRow, StatReport, TimelineRow, TimesReport, TreeNode, TreeReport, allocation_str,
    format_ts, node_kind_str, print_json, ts_unix_secs,
};
use forensic_image_cli::partition::{Partition, read_partitions};
use forensic_vfs::{DynFs, NodeKind};
use regex::RegexBuilder;

#[derive(Debug, Parser)]
#[command(
    name = "fimg",
    version,
    about = "Read-only forensic disk image browser and file extractor"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
    /// Emit machine-readable JSON instead of text.
    #[arg(long, global = true)]
    json: bool,
    /// Print a scan progress heartbeat to stderr (full-walk commands only).
    #[arg(long, global = true)]
    progress: bool,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Show container, disk, and filesystem metadata.
    Info {
        /// E01, VMDK, or raw disk image.
        image: PathBuf,
    },
    /// List detected MBR/GPT partitions and filesystems.
    Partitions {
        /// E01, VMDK, or raw disk image.
        image: PathBuf,
    },
    /// Print the image contents as a tree.
    Tree {
        /// E01, VMDK, or raw disk image.
        image: PathBuf,
        /// Restrict traversal to one displayed partition number.
        #[arg(short, long)]
        partition: Option<usize>,
        /// Do not descend beyond this path depth.
        #[arg(long)]
        max_depth: Option<usize>,
    },
    /// Search internal paths using a regular expression.
    Find {
        /// E01, VMDK, or raw disk image.
        image: PathBuf,
        /// Rust-compatible regular expression.
        pattern: String,
        /// Restrict traversal to one displayed partition number.
        #[arg(short, long)]
        partition: Option<usize>,
        /// Match without case sensitivity.
        #[arg(short = 'i', long)]
        ignore_case: bool,
    },
    /// Show metadata and MAC(B) timestamps for one path.
    Stat {
        /// E01, VMDK, or raw disk image.
        image: PathBuf,
        /// Absolute-style path inside the selected filesystem.
        path: String,
        /// Restrict lookup to one displayed partition number.
        #[arg(short, long)]
        partition: Option<usize>,
    },
    /// Emit a filesystem timeline (CSV, or Sleuth Kit bodyfile).
    Timeline {
        /// E01, VMDK, or raw disk image.
        image: PathBuf,
        /// Restrict traversal to one displayed partition number.
        #[arg(short, long)]
        partition: Option<usize>,
        /// Emit the Sleuth Kit bodyfile format instead of CSV.
        #[arg(long)]
        bodyfile: bool,
    },
    /// List deleted and orphaned nodes recoverable from each filesystem.
    Deleted {
        /// E01, VMDK, or raw disk image.
        image: PathBuf,
        /// Restrict enumeration to one displayed partition number.
        #[arg(short, long)]
        partition: Option<usize>,
    },
    /// Calculate MD5, SHA-1, and SHA-256 for an image or one internal file.
    Hash {
        /// E01, VMDK, or raw disk image.
        image: PathBuf,
        /// Optional absolute-style path inside a filesystem.
        path: Option<String>,
        /// Restrict lookup to one displayed partition number.
        #[arg(short, long, requires = "path")]
        partition: Option<usize>,
        /// Hash the supplied container file bytes instead of decoded virtual media.
        #[arg(long, conflicts_with = "path")]
        container: bool,
    },
    /// Recover one readable deleted file by inode/MFT number or recovered name.
    Recover {
        /// E01, VMDK, or raw disk image.
        image: PathBuf,
        /// Deleted inode or MFT record number.
        #[arg(long, conflicts_with = "name", required_unless_present = "name")]
        inode: Option<u64>,
        /// Recovered deleted filename (must identify exactly one entry).
        #[arg(long, conflicts_with = "inode", required_unless_present = "inode")]
        name: Option<String>,
        /// Destination path on the host.
        #[arg(short, long)]
        output: PathBuf,
        /// Restrict lookup to one displayed partition number.
        #[arg(short, long)]
        partition: Option<usize>,
        /// Replace an existing output file.
        #[arg(long)]
        overwrite: bool,
    },
    /// Extract one file by its path inside the image.
    Extract {
        /// E01, VMDK, or raw disk image.
        image: PathBuf,
        /// Absolute-style path inside the selected filesystem.
        path: String,
        /// Destination path on the host.
        #[arg(short, long)]
        output: PathBuf,
        /// Restrict lookup to one displayed partition number.
        #[arg(short, long)]
        partition: Option<usize>,
        /// Replace an existing output file.
        #[arg(long)]
        overwrite: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let format = OutputFormat::from_json_flag(cli.json);
    let progress = cli.progress;
    match cli.command {
        Command::Info { image } => command_info(&image, format),
        Command::Partitions { image } => command_partitions(&image, format),
        Command::Tree {
            image,
            partition,
            max_depth,
        } => command_tree(&image, partition, max_depth, progress, format),
        Command::Find {
            image,
            pattern,
            partition,
            ignore_case,
        } => command_find(&image, &pattern, partition, ignore_case, progress, format),
        Command::Stat {
            image,
            path,
            partition,
        } => command_stat(&image, &path, partition, format),
        Command::Timeline {
            image,
            partition,
            bodyfile,
        } => command_timeline(&image, partition, bodyfile, progress, format),
        Command::Deleted { image, partition } => {
            command_deleted(&image, partition, progress, format)
        }
        Command::Hash {
            image,
            path,
            partition,
            container,
        } => command_hash(&image, path.as_deref(), partition, container, format),
        Command::Recover {
            image,
            inode,
            name,
            output,
            partition,
            overwrite,
        } => command_recover(
            &image,
            inode,
            name.as_deref(),
            &output,
            partition,
            overwrite,
            format,
        ),
        Command::Extract {
            image,
            path,
            output,
            partition,
            overwrite,
        } => command_extract(&image, &path, &output, partition, overwrite, format),
    }
}

fn image_layout(image: &Path) -> Result<(ImageFactory, Vec<Partition>, u64)> {
    let factory = ImageFactory::detect(image)?;
    let mut opened = factory.open()?;
    let virtual_size = opened.virtual_size;
    let partitions = read_partitions(&mut opened.reader, virtual_size)?;
    Ok((factory, partitions, virtual_size))
}

fn select_partitions(
    partitions: &[Partition],
    requested: Option<usize>,
) -> Result<Vec<&Partition>> {
    match requested {
        Some(number) => {
            let partition = partitions
                .iter()
                .find(|partition| partition.number == number)
                .with_context(|| {
                    let available = partitions
                        .iter()
                        .map(|partition| format!("p{}", partition.number))
                        .collect::<Vec<_>>()
                        .join(", ");
                    format!("partition p{number} not found; available: {available}")
                })?;
            Ok(vec![partition])
        }
        None => Ok(partitions.iter().collect()),
    }
}

/// Opt-in scan heartbeat on stderr for the full-filesystem-walk commands.
///
/// `tree`, `find`, `timeline`, and `deleted` buffer their results and can run
/// for minutes on a large E01 with no output at all; `--progress` emits a
/// throttled entry count so the operator knows the scan is alive. It writes only
/// to stderr, leaving stdout data (tree/CSV/JSON) untouched: when stderr is a
/// terminal it repaints one line in place with a carriage return, otherwise it
/// emits plain lines suitable for a redirected log. Repaints are throttled to at
/// most one every 200 ms; `finish` prints the final total.
struct Progress {
    enabled: bool,
    tty: bool,
    count: u64,
    partition: usize,
    last: Instant,
}

impl Progress {
    fn new(enabled: bool) -> Self {
        Progress {
            enabled,
            tty: std::io::stderr().is_terminal(),
            count: 0,
            partition: 0,
            last: Instant::now(),
        }
    }

    /// Count one visited entry, repainting at most every 200 ms.
    fn tick(&mut self, partition: usize) {
        if !self.enabled {
            return;
        }
        self.count += 1;
        self.partition = partition;
        let now = Instant::now();
        if now.duration_since(self.last) >= Duration::from_millis(200) {
            self.last = now;
            self.emit(false);
        }
    }

    fn message(&self) -> String {
        format!("scanning p{}: {} entries", self.partition, self.count)
    }

    fn emit(&self, final_line: bool) {
        let mut stderr = std::io::stderr().lock();
        if self.tty {
            // Repaint in place; pad to overwrite a previously longer line.
            let _ = write!(stderr, "\r{:<60}", self.message());
            if final_line {
                let _ = writeln!(stderr);
            }
        } else {
            let _ = writeln!(stderr, "{}", self.message());
        }
        let _ = stderr.flush();
    }

    /// Emit the final total and terminate the progress line.
    fn finish(&self) {
        if !self.enabled || self.count == 0 {
            return;
        }
        self.emit(true);
    }
}

/// Walk the selected partitions, opening each supported filesystem exactly once.
///
/// Centralizes the multi-partition invariant: an unsupported filesystem is a
/// hard error when the user named a single partition (`requested.is_some()`) and
/// is otherwise skipped, with `on_skip` invoked so callers can warn. Opening
/// once (via `try_open_partition_filesystem`) replaces the former detect-then-open
/// pair, halving container opens on the reopen-per-operation path.
fn for_each_readable_partition(
    factory: &ImageFactory,
    partitions: &[Partition],
    requested: Option<usize>,
    on_skip: impl Fn(&Partition),
    mut visit: impl FnMut(&Partition, FileSystemKind, &DynFs) -> Result<()>,
) -> Result<()> {
    for partition in select_partitions(partitions, requested)? {
        match try_open_partition_filesystem(factory, partition)? {
            Some((kind, filesystem)) => visit(partition, kind, &filesystem)?,
            None => {
                if requested.is_some() {
                    bail!("p{} has an unsupported filesystem", partition.number);
                }
                on_skip(partition);
            }
        }
    }
    Ok(())
}

fn command_info(image: &Path, format: OutputFormat) -> Result<()> {
    let (factory, partitions, virtual_size) = image_layout(image)?;
    let host_size = std::fs::metadata(factory.path())?.len();
    let scheme = partitions
        .first()
        .map(|partition| partition.scheme.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let mut info_partitions = Vec::new();
    for partition in &partitions {
        let filesystem = detect_partition_filesystem(&factory, partition)?;
        info_partitions.push(InfoPartition {
            number: partition.number,
            filesystem: filesystem.to_string(),
            byte_offset: partition.byte_offset(),
            name: partition.name.clone(),
        });
    }

    match format {
        OutputFormat::Json => print_json(&InfoReport {
            path: factory.path().display().to_string(),
            container: factory.kind().to_string(),
            host_size,
            virtual_size,
            partition_scheme: scheme,
            partition_count: partitions.len(),
            partitions: info_partitions,
        }),
        OutputFormat::Text => {
            println!("Path: {}", factory.path().display());
            println!("Container: {}", factory.kind());
            println!("Host size: {host_size} bytes");
            println!("Virtual size: {virtual_size} bytes");
            println!("Partition scheme: {scheme}");
            println!("Partitions: {}", partitions.len());
            for partition in &info_partitions {
                println!(
                    "  p{}: {} at byte offset {} ({})",
                    partition.number,
                    partition.filesystem,
                    partition.byte_offset,
                    partition.name.as_deref().unwrap_or("unnamed")
                );
            }
            Ok(())
        }
    }
}

fn command_partitions(image: &Path, format: OutputFormat) -> Result<()> {
    let (factory, partitions, _virtual_size) = image_layout(image)?;
    let mut rows = Vec::new();
    for partition in &partitions {
        let filesystem = detect_partition_filesystem(&factory, partition)?;
        rows.push(PartitionRow {
            partition,
            filesystem: filesystem.to_string(),
            byte_offset: partition.byte_offset(),
            byte_len: partition.byte_len(),
        });
    }

    match format {
        OutputFormat::Json => print_json(&rows),
        OutputFormat::Text => {
            for row in &rows {
                let partition = row.partition;
                println!(
                    "p{}\t{}\tfs={}\tstart={}\tsectors={}\toffset={}\tbytes={}\ttype={}\t{}",
                    partition.number,
                    partition.scheme,
                    row.filesystem,
                    partition.start_lba,
                    partition.sectors,
                    row.byte_offset,
                    row.byte_len,
                    partition.type_id,
                    partition.name.as_deref().unwrap_or("-")
                );
            }
            Ok(())
        }
    }
}

fn command_tree(
    image: &Path,
    requested: Option<usize>,
    max_depth: Option<usize>,
    show_progress: bool,
    format: OutputFormat,
) -> Result<()> {
    let (factory, partitions, _virtual_size) = image_layout(image)?;
    let mut reports = Vec::new();
    let mut progress = Progress::new(show_progress);
    for_each_readable_partition(
        &factory,
        &partitions,
        requested,
        |partition| {
            if format == OutputFormat::Text {
                eprintln!(
                    "warning: skipping p{} (unsupported filesystem)",
                    partition.number
                );
            }
        },
        |partition, kind, filesystem| {
            match format {
                OutputFormat::Text => {
                    println!(
                        "[p{}] {} {}",
                        partition.number,
                        kind,
                        partition.name.as_deref().unwrap_or("")
                    );
                    walk_filesystem(filesystem.as_ref(), max_depth, |entry| {
                        progress.tick(partition.number);
                        let mut prefix = String::new();
                        for ancestor_is_last in &entry.ancestor_is_last {
                            prefix.push_str(if *ancestor_is_last { "    " } else { "│   " });
                        }
                        prefix.push_str(if entry.is_last {
                            "└── "
                        } else {
                            "├── "
                        });
                        let suffix = if entry.kind == NodeKind::Dir { "/" } else { "" };
                        println!("{prefix}{}{suffix}", entry.name);
                        Ok(())
                    })?;
                }
                OutputFormat::Json => {
                    let mut entries = Vec::new();
                    walk_filesystem(filesystem.as_ref(), max_depth, |entry| {
                        progress.tick(partition.number);
                        entries.push(TreeNode {
                            path: entry.path.clone(),
                            name: entry.name.clone(),
                            kind: node_kind_str(entry.kind).to_string(),
                            size: entry.size,
                            depth: entry.depth,
                        });
                        Ok(())
                    })?;
                    reports.push(TreeReport {
                        partition: partition.number,
                        filesystem: kind.to_string(),
                        name: partition.name.clone(),
                        entries,
                    });
                }
            }
            Ok(())
        },
    )?;
    progress.finish();
    if format == OutputFormat::Json {
        print_json(&reports)?;
    }
    Ok(())
}

fn command_find(
    image: &Path,
    pattern: &str,
    requested: Option<usize>,
    ignore_case: bool,
    show_progress: bool,
    format: OutputFormat,
) -> Result<()> {
    let expression = RegexBuilder::new(pattern)
        .case_insensitive(ignore_case)
        .build()
        .with_context(|| format!("invalid regular expression: '{pattern}'"))?;
    let (factory, partitions, _virtual_size) = image_layout(image)?;
    let mut matches = Vec::new();
    let mut progress = Progress::new(show_progress);
    for_each_readable_partition(
        &factory,
        &partitions,
        requested,
        |_partition| {},
        |partition, _kind, filesystem| {
            walk_filesystem(filesystem.as_ref(), None, |entry| {
                progress.tick(partition.number);
                if expression.is_match(&entry.path) {
                    matches.push(FindMatch {
                        partition: partition.number,
                        kind: node_kind_str(entry.kind).to_string(),
                        size: entry.size,
                        path: entry.path.clone(),
                    });
                }
                Ok(())
            })
        },
    )?;
    progress.finish();

    match format {
        OutputFormat::Json => print_json(&matches),
        OutputFormat::Text => {
            if matches.is_empty() {
                bail!("no matching paths");
            }
            for entry in &matches {
                println!(
                    "p{}\t{}\t{}\t{}",
                    entry.partition, entry.kind, entry.size, entry.path
                );
            }
            Ok(())
        }
    }
}

fn command_stat(
    image: &Path,
    internal_path: &str,
    requested: Option<usize>,
    format: OutputFormat,
) -> Result<()> {
    let (factory, partitions, _virtual_size) = image_layout(image)?;
    let mut found = Vec::new();
    for_each_readable_partition(
        &factory,
        &partitions,
        requested,
        |_partition| {},
        |partition, _kind, filesystem| {
            if let Some((_id, meta)) = try_resolve_path(filesystem.as_ref(), internal_path)? {
                found.push((partition.number, meta));
            }
            Ok(())
        },
    )?;
    if found.is_empty() {
        bail!("path not found in readable partitions: '{internal_path}'");
    }
    if found.len() > 1 {
        let locations = found
            .iter()
            .map(|(number, _)| format!("p{number}"))
            .collect::<Vec<_>>()
            .join(", ");
        bail!("path exists in multiple partitions ({locations}); pass --partition");
    }

    let (number, meta) = found.remove(0);
    let report = StatReport {
        partition: number,
        path: internal_path.to_string(),
        ino: meta.ino,
        kind: node_kind_str(meta.kind).to_string(),
        allocated: allocation_str(meta.allocated).to_string(),
        size: meta.size,
        nlink: meta.nlink,
        uid: meta.uid,
        gid: meta.gid,
        mode: meta.mode,
        mode_octal: meta.mode.map(|mode| format!("{mode:o}")),
        times: TimesReport::from(&meta.times),
    };

    match format {
        OutputFormat::Json => print_json(&report),
        OutputFormat::Text => {
            println!("Path: {}", report.path);
            println!("Partition: p{}", report.partition);
            println!("Inode/MFT: {}", report.ino);
            println!("Kind: {}", report.kind);
            println!("Allocated: {}", report.allocated);
            println!("Size: {} bytes", report.size);
            println!("Links: {}", report.nlink);
            print_owner("UID", report.uid);
            print_owner("GID", report.gid);
            match &report.mode_octal {
                Some(mode) => println!("Mode: 0{mode}"),
                None => println!("Mode: -"),
            }
            print_time("Modified", &report.times.modified);
            print_time("Accessed", &report.times.accessed);
            print_time("Changed", &report.times.changed);
            print_time("Born", &report.times.born);
            Ok(())
        }
    }
}

fn command_timeline(
    image: &Path,
    requested: Option<usize>,
    bodyfile: bool,
    show_progress: bool,
    format: OutputFormat,
) -> Result<()> {
    let (factory, partitions, _virtual_size) = image_layout(image)?;
    let mut rows = Vec::new();
    let mut progress = Progress::new(show_progress);
    for_each_readable_partition(
        &factory,
        &partitions,
        requested,
        |_partition| {},
        |partition, _kind, filesystem| {
            walk_filesystem(filesystem.as_ref(), None, |entry| {
                progress.tick(partition.number);
                rows.push((partition.number, entry.clone()));
                Ok(())
            })
        },
    )?;
    progress.finish();

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    match format {
        OutputFormat::Json => {
            let json_rows: Vec<TimelineRow> = rows
                .iter()
                .map(|(number, entry)| TimelineRow {
                    partition: *number,
                    path: entry.path.clone(),
                    kind: node_kind_str(entry.kind).to_string(),
                    size: entry.size,
                    modified: format_ts(entry.times.modified),
                    accessed: format_ts(entry.times.accessed),
                    changed: format_ts(entry.times.changed),
                    born: format_ts(entry.times.born),
                })
                .collect();
            drop(out);
            print_json(&json_rows)
        }
        OutputFormat::Text if bodyfile => {
            // Sleuth Kit bodyfile: MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime
            for (_number, entry) in &rows {
                writeln!(
                    out,
                    "0|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
                    bodyfile_name(&entry.path),
                    entry.ino,
                    entry.mode.unwrap_or(0),
                    entry.uid.unwrap_or(0),
                    entry.gid.unwrap_or(0),
                    entry.size,
                    ts_unix_secs(entry.times.accessed),
                    ts_unix_secs(entry.times.modified),
                    ts_unix_secs(entry.times.changed),
                    ts_unix_secs(entry.times.born),
                )?;
            }
            Ok(())
        }
        OutputFormat::Text => {
            writeln!(
                out,
                "partition,path,type,size,modified,accessed,changed,born"
            )?;
            for (number, entry) in &rows {
                writeln!(
                    out,
                    "p{},{},{},{},{},{},{},{}",
                    number,
                    csv_field(&entry.path),
                    node_kind_str(entry.kind),
                    entry.size,
                    csv_time(entry.times.modified),
                    csv_time(entry.times.accessed),
                    csv_time(entry.times.changed),
                    csv_time(entry.times.born),
                )?;
            }
            Ok(())
        }
    }
}

fn command_deleted(
    image: &Path,
    requested: Option<usize>,
    show_progress: bool,
    format: OutputFormat,
) -> Result<()> {
    let (factory, partitions, _virtual_size) = image_layout(image)?;
    let mut rows = Vec::new();
    let mut progress = Progress::new(show_progress);
    for_each_readable_partition(
        &factory,
        &partitions,
        requested,
        |_partition| {},
        |partition, _kind, filesystem| {
            for entry in list_deleted(filesystem.as_ref())? {
                progress.tick(partition.number);
                rows.push(deleted_row(partition.number, entry));
            }
            Ok(())
        },
    )?;
    progress.finish();

    match format {
        OutputFormat::Json => print_json(&rows),
        OutputFormat::Text => {
            for row in &rows {
                let name = row.name.as_deref().unwrap_or("");
                let label = if name.is_empty() {
                    format!("<{} inode {}>", row.allocated, row.ino)
                } else {
                    name.to_string()
                };
                println!(
                    "p{}\t{}\t{}\t{}\t{}",
                    row.partition, row.allocated, row.kind, row.size, label
                );
            }
            Ok(())
        }
    }
}

fn deleted_row(partition: usize, entry: DeletedEntry) -> DeletedRow {
    DeletedRow {
        partition,
        ino: entry.ino,
        name: entry.name,
        kind: node_kind_str(entry.kind).to_string(),
        allocated: allocation_str(entry.allocated).to_string(),
        size: entry.size,
        modified: format_ts(entry.times.modified),
        accessed: format_ts(entry.times.accessed),
        changed: format_ts(entry.times.changed),
        born: format_ts(entry.times.born),
    }
}

fn command_hash(
    image: &Path,
    internal_path: Option<&str>,
    requested: Option<usize>,
    container: bool,
    format: OutputFormat,
) -> Result<()> {
    let report = if container {
        let file = std::fs::File::open(image)
            .with_context(|| format!("cannot open container '{}'", image.display()))?;
        let (size, hashes) = hash_reader(file)?;
        HashReport {
            source: "container".to_string(),
            image: image.display().to_string(),
            partition: None,
            internal_path: None,
            size,
            hashes,
        }
    } else if let Some(path) = internal_path {
        let (factory, partitions, _virtual_size) = image_layout(image)?;
        let mut found = Vec::new();
        for_each_readable_partition(
            &factory,
            &partitions,
            requested,
            |_partition| {},
            |partition, _kind, filesystem| {
                if let Some((id, meta)) = try_resolve_path(filesystem.as_ref(), path)? {
                    found.push((partition.number, filesystem.clone(), id, meta));
                }
                Ok(())
            },
        )?;
        if found.is_empty() {
            bail!("path not found in readable partitions: '{path}'");
        }
        if found.len() > 1 {
            let locations = found
                .iter()
                .map(|(number, ..)| format!("p{number}"))
                .collect::<Vec<_>>()
                .join(", ");
            bail!("path exists in multiple partitions ({locations}); pass --partition");
        }
        let (partition, filesystem, id, meta) = found.remove(0);
        if meta.kind != NodeKind::File {
            bail!("internal path is not a regular file: '{path}'");
        }
        HashReport {
            source: "file".to_string(),
            image: factory.path().display().to_string(),
            partition: Some(partition),
            internal_path: Some(path.to_string()),
            size: meta.size,
            hashes: hash_node(filesystem.as_ref(), id, meta.size)?,
        }
    } else {
        let factory = ImageFactory::detect(image)?;
        let opened = factory.open()?;
        let (size, hashes) = hash_reader(opened.reader)?;
        HashReport {
            source: "virtual_image".to_string(),
            image: factory.path().display().to_string(),
            partition: None,
            internal_path: None,
            size,
            hashes,
        }
    };

    match format {
        OutputFormat::Json => print_json(&report),
        OutputFormat::Text => {
            println!("Source: {}", report.source);
            println!("Image: {}", report.image);
            if let Some(partition) = report.partition {
                println!("Partition: p{partition}");
            }
            if let Some(path) = &report.internal_path {
                println!("Internal path: {path}");
            }
            println!("Size: {} bytes", report.size);
            println!("MD5: {}", report.hashes.md5);
            println!("SHA-1: {}", report.hashes.sha1);
            println!("SHA-256: {}", report.hashes.sha256);
            Ok(())
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn command_recover(
    image: &Path,
    inode: Option<u64>,
    name: Option<&str>,
    output: &Path,
    requested: Option<usize>,
    overwrite: bool,
    format: OutputFormat,
) -> Result<()> {
    validate_destination(output, overwrite)?;
    let (factory, partitions, _virtual_size) = image_layout(image)?;
    let mut found = Vec::new();
    for_each_readable_partition(
        &factory,
        &partitions,
        requested,
        |_partition| {},
        |partition, kind, filesystem| {
            for entry in list_deleted(filesystem.as_ref())? {
                let matches = inode.is_some_and(|value| entry.ino == value)
                    || name.is_some_and(|value| {
                        entry
                            .name
                            .as_deref()
                            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(value))
                    });
                if matches {
                    found.push((partition.clone(), kind, filesystem.clone(), entry));
                }
            }
            Ok(())
        },
    )?;
    if found.is_empty() {
        bail!("no matching deleted file with readable identity");
    }
    if found.len() > 1 {
        let locations = found
            .iter()
            .map(|(partition, _, _, entry)| {
                format!(
                    "p{}:{}:{}",
                    partition.number,
                    entry.ino,
                    entry.name.as_deref().unwrap_or("<orphan>")
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        bail!("deleted selector is ambiguous ({locations}); narrow it with --partition or --inode");
    }

    let (partition, kind, filesystem, entry) = found.remove(0);
    if entry.kind != NodeKind::File {
        bail!("selected deleted node is not a regular file");
    }
    let id = entry.id.context(
        "filesystem reported deleted metadata without a readable identity; recovery is unavailable",
    )?;
    let digest = write_node_atomic(filesystem.as_ref(), id, entry.size, output, overwrite)?;
    let label = entry
        .name
        .unwrap_or_else(|| format!("<deleted inode {}>", entry.ino));
    let report = ExtractReport {
        extracted: output.display().to_string(),
        image: factory.path().display().to_string(),
        partition: partition.number,
        filesystem: kind.to_string(),
        internal_path: label,
        size: entry.size,
        sha256: hex_digest(&digest),
    };
    match format {
        OutputFormat::Json => print_json(&report),
        OutputFormat::Text => {
            println!("Recovered: {}", report.extracted);
            println!("Image: {}", report.image);
            println!("Partition: p{} ({})", report.partition, report.filesystem);
            println!(
                "Deleted entry: {} (inode/MFT {})",
                report.internal_path, entry.ino
            );
            println!("Size: {} bytes", report.size);
            println!("SHA-256: {}", report.sha256);
            println!(
                "Warning: deleted clusters may have been partially overwritten; verify independently."
            );
            Ok(())
        }
    }
}

fn command_extract(
    image: &Path,
    internal_path: &str,
    output: &Path,
    requested: Option<usize>,
    overwrite: bool,
    format: OutputFormat,
) -> Result<()> {
    validate_destination(output, overwrite)?;
    let (factory, partitions, _virtual_size) = image_layout(image)?;
    let mut found = Vec::new();
    for_each_readable_partition(
        &factory,
        &partitions,
        requested,
        |_partition| {},
        |partition, kind, filesystem| {
            if let Some((id, meta)) = try_resolve_path(filesystem.as_ref(), internal_path)? {
                found.push((partition.clone(), kind, filesystem.clone(), id, meta));
            }
            Ok(())
        },
    )?;
    if found.is_empty() {
        bail!("path not found in readable partitions: '{internal_path}'");
    }
    if found.len() > 1 {
        let locations = found
            .iter()
            .map(|(partition, ..)| format!("p{}", partition.number))
            .collect::<Vec<_>>()
            .join(", ");
        bail!("path exists in multiple partitions ({locations}); pass --partition");
    }

    let (partition, kind, filesystem, id, meta) = found.remove(0);
    if meta.kind != NodeKind::File {
        bail!("internal path is not a regular file: '{internal_path}'");
    }
    let digest = write_node_atomic(filesystem.as_ref(), id, meta.size, output, overwrite)?;

    let report = ExtractReport {
        extracted: output.display().to_string(),
        image: factory.path().display().to_string(),
        partition: partition.number,
        filesystem: kind.to_string(),
        internal_path: internal_path.to_string(),
        size: meta.size,
        sha256: hex_digest(&digest),
    };

    match format {
        OutputFormat::Json => print_json(&report),
        OutputFormat::Text => {
            println!("Extracted: {}", report.extracted);
            println!("Image: {}", report.image);
            println!("Partition: p{} ({})", report.partition, report.filesystem);
            println!("Internal path: {}", report.internal_path);
            println!("Size: {} bytes", report.size);
            println!("SHA-256: {}", report.sha256);
            Ok(())
        }
    }
}

fn validate_destination(output: &Path, overwrite: bool) -> Result<()> {
    if output.exists() && !overwrite {
        bail!(
            "destination already exists: '{}'; pass --overwrite to replace it",
            output.display()
        );
    }
    if output.is_dir() {
        bail!("destination is a directory: '{}'", output.display());
    }
    Ok(())
}

fn write_node_atomic(
    filesystem: &dyn forensic_vfs::FileSystem,
    id: forensic_vfs::FileId,
    size: u64,
    output: &Path,
    overwrite: bool,
) -> Result<[u8; 32]> {
    validate_destination(output, overwrite)?;
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)
        .with_context(|| format!("cannot create destination directory '{}'", parent.display()))?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).context("cannot create temporary output file")?;
    let digest = copy_file(filesystem, id, size, temporary.as_file_mut())?;
    temporary.as_file_mut().flush()?;
    temporary.as_file_mut().sync_all()?;
    if output.exists() {
        std::fs::remove_file(output)
            .with_context(|| format!("cannot replace destination '{}'", output.display()))?;
    }
    temporary
        .persist(output)
        .map_err(|error| error.error)
        .with_context(|| format!("cannot finalize destination '{}'", output.display()))?;

    Ok(digest)
}

fn print_owner(label: &str, value: Option<u32>) {
    match value {
        Some(value) => println!("{label}: {value}"),
        None => println!("{label}: -"),
    }
}

fn print_time(label: &str, value: &Option<String>) {
    println!("{label}: {}", value.as_deref().unwrap_or("-"));
}

fn csv_time(ts: Option<forensic_vfs::TimeStamp>) -> String {
    format_ts(ts).unwrap_or_default()
}

/// Quote a CSV field per RFC 4180 when it contains a comma, quote, or newline.
fn csv_field(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

/// Sanitize a path for a Sleuth Kit bodyfile `name` field.
///
/// The bodyfile format is `|`-delimited with one record per line and defines no
/// quoting, so a path containing `|`, CR, or LF would inject an extra field or
/// terminate the record early and desync downstream `mactime` parsing.
/// Percent-encode exactly those bytes — plus `%` itself, so the mapping stays
/// reversible — and pass every other character through unchanged.
fn bodyfile_name(value: &str) -> String {
    if !value.contains(['%', '|', '\n', '\r']) {
        return value.to_string();
    }
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '%' => out.push_str("%25"),
            '|' => out.push_str("%7C"),
            '\r' => out.push_str("%0D"),
            '\n' => out.push_str("%0A"),
            other => out.push(other),
        }
    }
    out
}

fn hex_digest(digest: &[u8]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::{Progress, bodyfile_name, csv_field};

    #[test]
    fn progress_disabled_never_counts() {
        let mut progress = Progress::new(false);
        for _ in 0..5 {
            progress.tick(0);
        }
        assert_eq!(progress.count, 0);
    }

    #[test]
    fn progress_enabled_counts_and_labels_current_partition() {
        let mut progress = Progress::new(true);
        progress.tick(2);
        progress.tick(2);
        progress.tick(3);
        assert_eq!(progress.count, 3);
        assert_eq!(progress.message(), "scanning p3: 3 entries");
    }

    #[test]
    fn bodyfile_name_passes_ordinary_paths_through() {
        assert_eq!(
            bodyfile_name("/docs/report final.txt"),
            "/docs/report final.txt"
        );
    }

    #[test]
    fn bodyfile_name_encodes_delimiter_and_line_breaks() {
        assert_eq!(bodyfile_name("/tmp/a|b\r\nc"), "/tmp/a%7Cb%0D%0Ac");
    }

    #[test]
    fn bodyfile_name_keeps_encoding_reversible_via_percent() {
        // A literal "%7C" must not be indistinguishable from an encoded '|'.
        assert_eq!(bodyfile_name("a%7Cb"), "a%257Cb");
        assert_eq!(bodyfile_name("a|b"), "a%7Cb");
    }

    #[test]
    fn encoded_bodyfile_name_stays_a_single_field_on_one_line() {
        let record = format!("0|{}|1|2|3|4|5|6|7|8|9", bodyfile_name("x|y\nz"));
        assert_eq!(record.matches('|').count(), 10, "exactly 11 fields");
        assert_eq!(record.lines().count(), 1, "one record per line");
    }

    #[test]
    fn csv_field_quotes_only_when_needed() {
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("she said \"hi\""), "\"she said \"\"hi\"\"\"");
    }
}
