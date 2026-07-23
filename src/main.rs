use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use forensic_image_cli::filesystem::{
    FileSystemKind, copy_file, detect_partition_filesystem, open_partition_filesystem,
    try_resolve_path, walk_filesystem,
};
use forensic_image_cli::image::ImageFactory;
use forensic_image_cli::partition::{Partition, read_partitions};
use forensic_vfs::NodeKind;
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
    match cli.command {
        Command::Info { image } => command_info(&image),
        Command::Partitions { image } => command_partitions(&image),
        Command::Tree {
            image,
            partition,
            max_depth,
        } => command_tree(&image, partition, max_depth),
        Command::Find {
            image,
            pattern,
            partition,
            ignore_case,
        } => command_find(&image, &pattern, partition, ignore_case),
        Command::Extract {
            image,
            path,
            output,
            partition,
            overwrite,
        } => command_extract(&image, &path, &output, partition, overwrite),
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

fn command_info(image: &Path) -> Result<()> {
    let (factory, partitions, virtual_size) = image_layout(image)?;
    let host_size = std::fs::metadata(factory.path())?.len();
    println!("Path: {}", factory.path().display());
    println!("Container: {}", factory.kind());
    println!("Host size: {host_size} bytes");
    println!("Virtual size: {virtual_size} bytes");
    println!(
        "Partition scheme: {}",
        partitions
            .first()
            .map(|partition| partition.scheme.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    );
    println!("Partitions: {}", partitions.len());
    for partition in &partitions {
        let filesystem = detect_partition_filesystem(&factory, partition)?;
        println!(
            "  p{}: {} at byte offset {} ({})",
            partition.number,
            filesystem,
            partition.byte_offset(),
            partition.name.as_deref().unwrap_or("unnamed")
        );
    }
    Ok(())
}

fn command_partitions(image: &Path) -> Result<()> {
    let (factory, partitions, _virtual_size) = image_layout(image)?;
    for partition in partitions {
        let filesystem = detect_partition_filesystem(&factory, &partition)?;
        println!(
            "p{}\t{}\tfs={}\tstart={}\tsectors={}\toffset={}\tbytes={}\ttype={}\t{}",
            partition.number,
            partition.scheme,
            filesystem,
            partition.start_lba,
            partition.sectors,
            partition.byte_offset(),
            partition.byte_len(),
            partition.type_id,
            partition.name.as_deref().unwrap_or("-")
        );
    }
    Ok(())
}

fn command_tree(image: &Path, requested: Option<usize>, max_depth: Option<usize>) -> Result<()> {
    let (factory, partitions, _virtual_size) = image_layout(image)?;
    for partition in select_partitions(&partitions, requested)? {
        let detected = detect_partition_filesystem(&factory, partition)?;
        if detected == FileSystemKind::Unknown {
            if requested.is_some() {
                bail!("p{} has an unsupported filesystem", partition.number);
            }
            eprintln!(
                "warning: skipping p{} (unsupported filesystem)",
                partition.number
            );
            continue;
        }
        let (kind, filesystem) = open_partition_filesystem(&factory, partition)?;
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
    Ok(())
}

fn command_find(
    image: &Path,
    pattern: &str,
    requested: Option<usize>,
    ignore_case: bool,
) -> Result<()> {
    let expression = RegexBuilder::new(pattern)
        .case_insensitive(ignore_case)
        .build()
        .with_context(|| format!("invalid regular expression: '{pattern}'"))?;
    let (factory, partitions, _virtual_size) = image_layout(image)?;
    let mut matches = 0_u64;
    for partition in select_partitions(&partitions, requested)? {
        let detected = detect_partition_filesystem(&factory, partition)?;
        if detected == FileSystemKind::Unknown {
            if requested.is_some() {
                bail!("p{} has an unsupported filesystem", partition.number);
            }
            continue;
        }
        let (_kind, filesystem) = open_partition_filesystem(&factory, partition)?;
        walk_filesystem(filesystem.as_ref(), None, |entry| {
            if expression.is_match(&entry.path) {
                println!(
                    "p{}\t{}\t{}\t{}",
                    partition.number,
                    node_kind(entry.kind),
                    entry.size,
                    entry.path
                );
                matches += 1;
            }
            Ok(())
        })?;
    }
    if matches == 0 {
        bail!("no matching paths");
    }
    Ok(())
}

fn command_extract(
    image: &Path,
    internal_path: &str,
    output: &Path,
    requested: Option<usize>,
    overwrite: bool,
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
    for partition in select_partitions(&partitions, requested)? {
        if detect_partition_filesystem(&factory, partition)? == FileSystemKind::Unknown {
            continue;
        }
        let (kind, filesystem) = open_partition_filesystem(&factory, partition)?;
        if let Some((id, meta)) = try_resolve_path(filesystem.as_ref(), internal_path)? {
            found.push((partition.clone(), kind, filesystem, id, meta));
        }
    }
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

    println!("Extracted: {}", output.display());
    println!("Image: {}", factory.path().display());
    println!("Partition: p{} ({kind})", partition.number);
    println!("Internal path: {internal_path}");
    println!("Size: {} bytes", meta.size);
    println!("SHA-256: {}", hex_digest(&digest));
    Ok(())
}

fn node_kind(kind: NodeKind) -> &'static str {
    match kind {
        NodeKind::File => "file",
        NodeKind::Dir => "dir",
        NodeKind::Symlink => "symlink",
        NodeKind::Device => "device",
        _ => "other",
    }
}

fn hex_digest(digest: &[u8]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}
