use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

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
    anyhow::bail!(
        "{:?} is scaffolded but not implemented yet; follow repository progress",
        cli.command
    )
}
