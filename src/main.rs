use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use forensic_image_cli::image::ImageFactory;
use forensic_image_cli::partition::read_partitions;

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
        Command::Info { image } => {
            let factory = ImageFactory::detect(&image)?;
            let mut opened = factory.open()?;
            let host_size = std::fs::metadata(factory.path())?.len();
            let partitions = read_partitions(&mut opened.reader, opened.virtual_size)?;
            println!("Path: {}", factory.path().display());
            println!("Container: {}", opened.kind);
            println!("Host size: {host_size} bytes");
            println!("Virtual size: {} bytes", opened.virtual_size);
            println!(
                "Partition scheme: {}",
                partitions
                    .first()
                    .map(|partition| partition.scheme.to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            );
            println!("Partitions: {}", partitions.len());
            Ok(())
        }
        Command::Partitions { image } => {
            let factory = ImageFactory::detect(&image)?;
            let mut opened = factory.open()?;
            for partition in read_partitions(&mut opened.reader, opened.virtual_size)? {
                println!(
                    "p{}\t{}\tstart={}\tsectors={}\toffset={}\tbytes={}\ttype={}\t{}",
                    partition.number,
                    partition.scheme,
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
        command => anyhow::bail!("{command:?} is not implemented yet"),
    }
}
