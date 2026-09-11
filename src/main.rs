use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use forensic_image_cli::carve::scan_signatures;
use forensic_image_cli::digest::{Hashes, hash_node, hash_reader};
use forensic_image_cli::filesystem::{
    DeletedEntry, FileSystemKind, copy_file, detect_partition_filesystem, list_deleted,
    try_open_partition_filesystem, try_resolve_path, walk_filesystem,
};
use forensic_image_cli::hunt::{HuntReport, ScanOptions, ScanSource, scan_node, scan_reader};
use forensic_image_cli::image::ImageFactory;
use forensic_image_cli::output::{
    DeletedRow, ExtractReport, FindMatch, HashReport, InfoPartition, InfoReport, OutputFormat,
    PartitionRow, StatReport, TimelineRow, TimesReport, TreeNode, TreeReport, allocation_str,
    format_ts, node_kind_str, print_json, ts_unix_secs,
};
use forensic_image_cli::partition::{Partition, read_partitions};
use forensic_image_cli::triage::{TriageCollector, TriageImage, TriagePartition, TriageReport};
use forensic_vfs::{DynFs, NodeKind};
use regex::RegexBuilder;
use regex::bytes::RegexBuilder as BytesRegexBuilder;
use serde::Serialize;

const DEFAULT_HUNT_PATTERN: &str =
    r"(?i)(?:flag|ctf|dfc|password|secret|recovery[ _-]?key|bitlocker)";

#[derive(Debug, Clone, Copy, ValueEnum)]
enum HuntScope {
    Files,
    Raw,
    All,
}

impl HuntScope {
    fn includes_files(self) -> bool {
        matches!(self, Self::Files | Self::All)
    }

    fn includes_raw(self) -> bool {
        matches!(self, Self::Raw | Self::All)
    }
}

impl std::fmt::Display for HuntScope {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Files => "files",
            Self::Raw => "raw",
            Self::All => "all",
        })
    }
}

#[derive(Debug, Serialize)]
struct RawExtractReport {
    image: String,
    offset: u64,
    length: u64,
    output: String,
    #[serde(flatten)]
    hashes: Hashes,
}

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
    /// Run a fast CTF-oriented inventory and suspicious-artifact triage.
    Triage {
        /// E01, VMDK, or raw disk image.
        image: PathBuf,
        /// Restrict filesystem triage to one displayed partition number.
        #[arg(short, long)]
        partition: Option<usize>,
        /// Skip MD5/SHA-1/SHA-256 calculation over decoded virtual media.
        #[arg(long)]
        no_hash: bool,
        /// Retain at most this many suspicious findings.
        #[arg(long, default_value_t = 1000)]
        max_findings: usize,
    },
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
    /// Search file contents or raw media for CTF flags, secrets, and other regex matches.
    Hunt {
        /// E01, VMDK, or raw disk image.
        image: PathBuf,
        /// Byte-oriented regular expression (defaults to common CTF evidence keywords).
        #[arg(default_value = DEFAULT_HUNT_PATTERN)]
        pattern: String,
        /// Search allocated files, decoded raw media, or both.
        #[arg(long, value_enum, default_value_t = HuntScope::Files)]
        scope: HuntScope,
        /// Restrict filesystem scanning to one displayed partition number.
        #[arg(short, long)]
        partition: Option<usize>,
        /// Match ASCII without case sensitivity.
        #[arg(short = 'i', long)]
        ignore_case: bool,
        /// Skip allocated files larger than this many bytes (0 means unlimited).
        #[arg(long, default_value_t = 268_435_456)]
        max_file_size: u64,
        /// Stop after this many matches.
        #[arg(long, default_value_t = 500)]
        max_matches: usize,
        /// Printable context characters to retain on each side of a match.
        #[arg(long, default_value_t = 80)]
        context: usize,
        /// Disable the automatic UTF-16LE pass.
        #[arg(long)]
        no_utf16: bool,
    },
    /// Locate common embedded file signatures across decoded media.
    Carve {
        /// E01, VMDK, or raw disk image.
        image: PathBuf,
        /// Restrict candidates to a type or extension such as png, pdf, zip, or exe.
        #[arg(long = "type")]
        type_filter: Option<String>,
        /// Stop after this many candidates.
        #[arg(long, default_value_t = 10_000)]
        max_candidates: usize,
    },
    /// Extract an exact byte range from decoded media without mounting it.
    RawExtract {
        /// E01, VMDK, or raw disk image.
        image: PathBuf,
        /// Virtual-media byte offset, decimal or 0x-prefixed hexadecimal.
        #[arg(long, value_parser = parse_offset)]
        offset: u64,
        /// Number of bytes to extract, decimal or 0x-prefixed hexadecimal.
        #[arg(long, value_parser = parse_offset)]
        length: u64,
        /// Destination path on the host.
        #[arg(short, long)]
        output: PathBuf,
        /// Replace an existing output file.
        #[arg(long)]
        overwrite: bool,
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
        Command::Triage {
            image,
            partition,
            no_hash,
            max_findings,
        } => command_triage(&image, partition, no_hash, max_findings, progress, format),
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
        Command::Hunt {
            image,
            pattern,
            scope,
            partition,
            ignore_case,
            max_file_size,
            max_matches,
            context,
            no_utf16,
        } => command_hunt(
            &image,
            &pattern,
            scope,
            partition,
            ignore_case,
            max_file_size,
            max_matches,
            context,
            !no_utf16,
            progress,
            format,
        ),
        Command::Carve {
            image,
            type_filter,
            max_candidates,
        } => command_carve(&image, type_filter.as_deref(), max_candidates, format),
        Command::RawExtract {
            image,
            offset,
            length,
            output,
            overwrite,
        } => command_raw_extract(&image, offset, length, &output, overwrite, format),
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

fn command_triage(
    image: &Path,
    requested: Option<usize>,
    no_hash: bool,
    max_findings: usize,
    show_progress: bool,
    format: OutputFormat,
) -> Result<()> {
    if max_findings == 0 || max_findings > 100_000 {
        bail!("--max-findings must be between 1 and 100000");
    }
    let (factory, partitions, virtual_size) = image_layout(image)?;
    let host_size = std::fs::metadata(factory.path())?.len();
    let virtual_hashes = if no_hash {
        None
    } else {
        let opened = factory.open()?;
        let (hashed_size, hashes) = hash_reader(opened.reader)?;
        if hashed_size != virtual_size {
            bail!(
                "decoded image size changed while hashing: expected {virtual_size}, read {hashed_size}"
            );
        }
        Some(hashes)
    };

    let mut partition_reports = Vec::new();
    for partition in &partitions {
        partition_reports.push(TriagePartition {
            number: partition.number,
            filesystem: detect_partition_filesystem(&factory, partition)?.to_string(),
            byte_offset: partition.byte_offset(),
            byte_len: partition.byte_len(),
            name: partition.name.clone(),
        });
    }

    let mut collector = TriageCollector::new(max_findings);
    let mut progress = Progress::new(show_progress);
    for partition in select_partitions(&partitions, requested)? {
        match try_open_partition_filesystem(&factory, partition)? {
            Some((_kind, filesystem)) => {
                walk_filesystem(filesystem.as_ref(), None, |entry| {
                    progress.tick(partition.number);
                    collector.inspect_entry(partition.number, filesystem.as_ref(), entry);
                    Ok(())
                })?;
                for deleted in list_deleted(filesystem.as_ref())? {
                    progress.tick(partition.number);
                    collector.note_deleted(
                        partition.number,
                        deleted.ino,
                        deleted.name.as_deref(),
                        deleted.size,
                        deleted.id.is_some() && deleted.kind == NodeKind::File,
                    );
                }
            }
            None => {
                let detected = detect_partition_filesystem(&factory, partition)?;
                let (kind, detail) = match detected {
                    FileSystemKind::BitLocker => (
                        "encrypted_bitlocker",
                        "BitLocker volume detected; search companion memory or key material for a recovery key",
                    ),
                    FileSystemKind::Luks => (
                        "encrypted_luks",
                        "LUKS volume detected; locate passphrases or key slots before filesystem analysis",
                    ),
                    _ => (
                        "unsupported_filesystem",
                        "filesystem is unsupported or unrecognized; raw hunt and carving may still find evidence",
                    ),
                };
                collector.note_partition_issue(partition.number, kind, detail.to_string());
            }
        }
    }
    progress.finish();
    collector.findings.sort_by(|left, right| {
        severity_rank(&right.severity)
            .cmp(&severity_rank(&left.severity))
            .then_with(|| left.kind.cmp(&right.kind))
            .then_with(|| left.path.cmp(&right.path))
    });

    let image_arg = factory.path().display().to_string();
    let report = TriageReport {
        image: TriageImage {
            path: image_arg.clone(),
            container: factory.kind().to_string(),
            host_size,
            virtual_size,
            virtual_hashes,
        },
        partitions: partition_reports,
        summary: collector.summary,
        findings_truncated: collector.truncated,
        findings: collector.findings,
        next_steps: vec![
            format!("fimg hunt \"{image_arg}\" --scope files --json"),
            format!("fimg hunt \"{image_arg}\" --scope raw --json"),
            format!("fimg deleted \"{image_arg}\" --json"),
            format!("fimg timeline \"{image_arg}\" --json"),
        ],
    };

    match format {
        OutputFormat::Json => print_json(&report),
        OutputFormat::Text => {
            println!("Image: {}", report.image.path);
            println!("Container: {}", report.image.container);
            println!("Host size: {} bytes", report.image.host_size);
            println!("Virtual size: {} bytes", report.image.virtual_size);
            if let Some(hashes) = &report.image.virtual_hashes {
                println!("Virtual MD5: {}", hashes.md5);
                println!("Virtual SHA-1: {}", hashes.sha1);
                println!("Virtual SHA-256: {}", hashes.sha256);
            }
            println!("Partitions:");
            for partition in &report.partitions {
                println!(
                    "  p{}\t{}\toffset={}\tbytes={}\t{}",
                    partition.number,
                    partition.filesystem,
                    partition.byte_offset,
                    partition.byte_len,
                    partition.name.as_deref().unwrap_or("-")
                );
            }
            println!(
                "Summary: {} files, {} directories, {} deleted ({} recoverable), {} findings",
                report.summary.files,
                report.summary.directories,
                report.summary.deleted_entries,
                report.summary.recoverable_deleted_files,
                report.summary.suspicious_findings
            );
            for finding in &report.findings {
                println!(
                    "[{}] p{} {} {} -- {}",
                    finding.severity.to_ascii_uppercase(),
                    finding.partition,
                    finding.kind,
                    finding.path.as_deref().unwrap_or("<partition>"),
                    finding.detail
                );
            }
            if report.findings_truncated {
                println!("[!] finding list truncated; raise --max-findings for the full list");
            }
            println!("Next steps:");
            for step in &report.next_steps {
                println!("  {step}");
            }
            Ok(())
        }
    }
}

fn severity_rank(severity: &str) -> u8 {
    match severity {
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn parse_offset(value: &str) -> std::result::Result<u64, String> {
    let value = value.trim();
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).map_err(|error| format!("invalid hexadecimal value: {error}"))
    } else {
        value
            .parse::<u64>()
            .map_err(|error| format!("invalid decimal value: {error}"))
    }
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

#[allow(clippy::too_many_arguments)]
fn command_hunt(
    image: &Path,
    pattern: &str,
    scope: HuntScope,
    requested: Option<usize>,
    ignore_case: bool,
    max_file_size: u64,
    max_matches: usize,
    context: usize,
    utf16le: bool,
    show_progress: bool,
    format: OutputFormat,
) -> Result<()> {
    if max_matches == 0 || max_matches > 100_000 {
        bail!("--max-matches must be between 1 and 100000");
    }
    if context > 4096 {
        bail!("--context cannot exceed 4096");
    }
    if requested.is_some() && !scope.includes_files() {
        bail!("--partition only applies when --scope includes files");
    }
    let expression = BytesRegexBuilder::new(pattern)
        .case_insensitive(ignore_case)
        .build()
        .with_context(|| format!("invalid byte regular expression: '{pattern}'"))?;
    let scan_options = ScanOptions {
        max_matches,
        context,
        utf16le,
    };
    let (factory, partitions, _virtual_size) = image_layout(image)?;
    let mut report = HuntReport::new(pattern, &scope.to_string());
    let mut progress = Progress::new(show_progress);

    if scope.includes_files() {
        for_each_readable_partition(
            &factory,
            &partitions,
            requested,
            |_partition| {},
            |partition, _kind, filesystem| {
                walk_filesystem(filesystem.as_ref(), None, |entry| {
                    progress.tick(partition.number);
                    if entry.kind != NodeKind::File || report.matches.len() >= max_matches {
                        return Ok(());
                    }
                    if max_file_size != 0 && entry.size > max_file_size {
                        report.skipped_large_files += 1;
                        return Ok(());
                    }
                    report.scanned_files += 1;
                    let source = ScanSource {
                        source: "file",
                        partition: Some(partition.number),
                        path: Some(entry.path.clone()),
                    };
                    if let Err(error) = scan_node(
                        filesystem.as_ref(),
                        entry.id,
                        entry.size,
                        &expression,
                        &source,
                        scan_options,
                        &mut report,
                    ) {
                        report.unreadable_files += 1;
                        if format == OutputFormat::Text {
                            eprintln!(
                                "warning: cannot scan p{}:{}: {error:#}",
                                partition.number, entry.path
                            );
                        }
                    }
                    Ok(())
                })
            },
        )?;
    }

    if scope.includes_raw() && report.matches.len() < max_matches {
        let opened = factory.open()?;
        scan_reader(
            opened.reader,
            &expression,
            &ScanSource {
                source: "raw",
                partition: None,
                path: None,
            },
            scan_options,
            &mut report,
        )?;
    }
    progress.finish();

    match format {
        OutputFormat::Json => print_json(&report),
        OutputFormat::Text => {
            for found in &report.matches {
                let location = found
                    .path
                    .as_deref()
                    .map(|path| {
                        format!(
                            "p{}:{path}",
                            found
                                .partition
                                .map_or("?".to_string(), |value| value.to_string())
                        )
                    })
                    .unwrap_or_else(|| "<virtual-image>".to_string());
                println!(
                    "{}\t{}\t{}\t{}\t{}",
                    found.source, location, found.offset, found.encoding, found.context
                );
            }
            eprintln!(
                "hunt: {} matches, {} files, {} bytes{}",
                report.matches.len(),
                report.scanned_files,
                report.scanned_bytes,
                if report.truncated { " (truncated)" } else { "" }
            );
            Ok(())
        }
    }
}

fn command_carve(
    image: &Path,
    type_filter: Option<&str>,
    max_candidates: usize,
    format: OutputFormat,
) -> Result<()> {
    if max_candidates == 0 || max_candidates > 1_000_000 {
        bail!("--max-candidates must be between 1 and 1000000");
    }
    let factory = ImageFactory::detect(image)?;
    let opened = factory.open()?;
    let report = scan_signatures(
        opened.reader,
        &factory.path().display().to_string(),
        opened.virtual_size,
        type_filter,
        max_candidates,
    )?;
    match format {
        OutputFormat::Json => print_json(&report),
        OutputFormat::Text => {
            for candidate in &report.candidates {
                println!(
                    "{}\t{}\t.{}\t{}",
                    candidate.offset,
                    candidate.kind,
                    candidate.suggested_extension,
                    candidate.header_hex
                );
            }
            eprintln!(
                "carve: {} candidates in {} bytes{}",
                report.candidates.len(),
                report.scanned_bytes,
                if report.truncated { " (truncated)" } else { "" }
            );
            Ok(())
        }
    }
}

fn command_raw_extract(
    image: &Path,
    offset: u64,
    length: u64,
    output: &Path,
    overwrite: bool,
    format: OutputFormat,
) -> Result<()> {
    if length == 0 {
        bail!("--length must be greater than zero");
    }
    validate_destination(output, overwrite)?;
    let factory = ImageFactory::detect(image)?;
    let mut opened = factory.open()?;
    let end = offset.checked_add(length).context("byte range overflow")?;
    if end > opened.virtual_size {
        bail!(
            "requested range {offset}..{end} exceeds virtual image size {}",
            opened.virtual_size
        );
    }
    use std::io::{Read as _, Seek as _, SeekFrom};
    opened
        .reader
        .seek(SeekFrom::Start(offset))
        .context("cannot seek to raw extraction offset")?;
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)
        .with_context(|| format!("cannot create destination directory '{}'", parent.display()))?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).context("cannot create temporary output file")?;
    let copied = std::io::copy(&mut opened.reader.take(length), temporary.as_file_mut())
        .context("cannot copy decoded byte range")?;
    if copied != length {
        bail!("unexpected end of image after {copied} of {length} requested bytes");
    }
    temporary.as_file_mut().flush()?;
    temporary.as_file_mut().sync_all()?;
    let (hashed_size, hashes) = hash_reader(temporary.reopen()?)?;
    if hashed_size != length {
        bail!("temporary extraction size changed before hashing");
    }
    if output.exists() {
        std::fs::remove_file(output)
            .with_context(|| format!("cannot replace destination '{}'", output.display()))?;
    }
    temporary
        .persist(output)
        .map_err(|error| error.error)
        .with_context(|| format!("cannot finalize destination '{}'", output.display()))?;

    let report = RawExtractReport {
        image: factory.path().display().to_string(),
        offset,
        length,
        output: output.display().to_string(),
        hashes,
    };
    match format {
        OutputFormat::Json => print_json(&report),
        OutputFormat::Text => {
            println!("Extracted raw range: {}", report.output);
            println!("Image: {}", report.image);
            println!("Offset: {} (0x{:x})", report.offset, report.offset);
            println!("Length: {} bytes", report.length);
            println!("MD5: {}", report.hashes.md5);
            println!("SHA-1: {}", report.hashes.sha1);
            println!("SHA-256: {}", report.hashes.sha256);
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
