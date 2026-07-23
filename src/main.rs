use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use forensic_image_cli::filesystem::{
    DeletedEntry, FileSystemKind, copy_file, detect_partition_filesystem, list_deleted,
    try_open_partition_filesystem, try_resolve_path, walk_filesystem,
};
use forensic_image_cli::image::ImageFactory;
use forensic_image_cli::output::{
    DeletedRow, ExtractReport, FindMatch, InfoPartition, InfoReport, OutputFormat, PartitionRow,
    StatReport, TimelineRow, TimesReport, TreeNode, TreeReport, allocation_str, format_ts,
    node_kind_str, print_json, ts_unix_secs,
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
    match cli.command {
        Command::Info { image } => command_info(&image, format),
        Command::Partitions { image } => command_partitions(&image, format),
        Command::Tree {
            image,
            partition,
            max_depth,
        } => command_tree(&image, partition, max_depth, format),
        Command::Find {
            image,
            pattern,
            partition,
            ignore_case,
        } => command_find(&image, &pattern, partition, ignore_case, format),
        Command::Stat {
            image,
            path,
            partition,
        } => command_stat(&image, &path, partition, format),
        Command::Timeline {
            image,
            partition,
            bodyfile,
        } => command_timeline(&image, partition, bodyfile, format),
        Command::Deleted { image, partition } => command_deleted(&image, partition, format),
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
    format: OutputFormat,
) -> Result<()> {
    let (factory, partitions, _virtual_size) = image_layout(image)?;
    let mut reports = Vec::new();
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
    format: OutputFormat,
) -> Result<()> {
    let expression = RegexBuilder::new(pattern)
        .case_insensitive(ignore_case)
        .build()
        .with_context(|| format!("invalid regular expression: '{pattern}'"))?;
    let (factory, partitions, _virtual_size) = image_layout(image)?;
    let mut matches = Vec::new();
    for_each_readable_partition(
        &factory,
        &partitions,
        requested,
        |_partition| {},
        |partition, _kind, filesystem| {
            walk_filesystem(filesystem.as_ref(), None, |entry| {
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
    format: OutputFormat,
) -> Result<()> {
    let (factory, partitions, _virtual_size) = image_layout(image)?;
    let mut rows = Vec::new();
    for_each_readable_partition(
        &factory,
        &partitions,
        requested,
        |_partition| {},
        |partition, _kind, filesystem| {
            walk_filesystem(filesystem.as_ref(), None, |entry| {
                rows.push((partition.number, entry.clone()));
                Ok(())
            })
        },
    )?;

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
                    entry.path,
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

fn command_deleted(image: &Path, requested: Option<usize>, format: OutputFormat) -> Result<()> {
    let (factory, partitions, _virtual_size) = image_layout(image)?;
    let mut rows = Vec::new();
    for_each_readable_partition(
        &factory,
        &partitions,
        requested,
        |_partition| {},
        |partition, _kind, filesystem| {
            for entry in list_deleted(filesystem.as_ref())? {
                rows.push(deleted_row(partition.number, entry));
            }
            Ok(())
        },
    )?;

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

fn command_extract(
    image: &Path,
    internal_path: &str,
    output: &Path,
    requested: Option<usize>,
    overwrite: bool,
    format: OutputFormat,
) -> Result<()> {
    if output.exists() && !overwrite {
        bail!(
            "destination already exists: '{}'; pass --overwrite to replace it",
            output.display()
        );
    }
    if output.is_dir() {
        bail!("destination is a directory: '{}'", output.display());
    }
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
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)
        .with_context(|| format!("cannot create destination directory '{}'", parent.display()))?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).context("cannot create temporary output file")?;
    let digest = copy_file(filesystem.as_ref(), id, meta.size, temporary.as_file_mut())?;
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

fn hex_digest(digest: &[u8]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}
