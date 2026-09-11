use std::io::Read;

use anyhow::{Context, Result, bail};
use forensic_vfs::{FileId, FileSystem, StreamId};
use regex::bytes::Regex;
use serde::Serialize;

const CHUNK_SIZE: usize = 1024 * 1024;
const OVERLAP: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct HuntMatch {
    pub source: String,
    pub partition: Option<usize>,
    pub path: Option<String>,
    pub offset: u64,
    pub encoding: String,
    pub matched: String,
    pub context: String,
}

#[derive(Debug, Serialize)]
pub struct HuntReport {
    pub pattern: String,
    pub scope: String,
    pub scanned_files: u64,
    pub scanned_bytes: u64,
    pub skipped_large_files: u64,
    pub unreadable_files: u64,
    pub truncated: bool,
    pub matches: Vec<HuntMatch>,
}

impl HuntReport {
    pub fn new(pattern: &str, scope: &str) -> Self {
        Self {
            pattern: pattern.to_string(),
            scope: scope.to_string(),
            scanned_files: 0,
            scanned_bytes: 0,
            skipped_large_files: 0,
            unreadable_files: 0,
            truncated: false,
            matches: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScanSource {
    pub source: &'static str,
    pub partition: Option<usize>,
    pub path: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct ScanOptions {
    pub max_matches: usize,
    pub context: usize,
    pub utf16le: bool,
}

pub fn scan_reader(
    mut reader: impl Read,
    expression: &Regex,
    source: &ScanSource,
    options: ScanOptions,
    report: &mut HuntReport,
) -> Result<()> {
    scan_chunks(
        |buffer| reader.read(buffer).context("cannot read image content"),
        expression,
        source,
        options,
        report,
    )
}

pub fn scan_node(
    filesystem: &dyn FileSystem,
    id: FileId,
    size: u64,
    expression: &Regex,
    source: &ScanSource,
    options: ScanOptions,
    report: &mut HuntReport,
) -> Result<()> {
    let mut offset = 0_u64;
    scan_chunks(
        |buffer| {
            if offset >= size {
                return Ok(0);
            }
            let wanted = (size - offset).min(buffer.len() as u64) as usize;
            let read = filesystem
                .read_at(id, StreamId::Default, offset, &mut buffer[..wanted])
                .with_context(|| format!("cannot read file at byte offset {offset}"))?;
            if read == 0 && offset < size {
                bail!("unexpected end of file at byte offset {offset} of {size}");
            }
            offset += read as u64;
            Ok(read)
        },
        expression,
        source,
        options,
        report,
    )
}

fn scan_chunks(
    mut read: impl FnMut(&mut [u8]) -> Result<usize>,
    expression: &Regex,
    source: &ScanSource,
    options: ScanOptions,
    report: &mut HuntReport,
) -> Result<()> {
    let mut buffer = vec![0_u8; CHUNK_SIZE];
    let mut tail = Vec::new();
    let mut consumed = 0_u64;
    loop {
        let count = read(&mut buffer)?;
        if count == 0 {
            break;
        }
        let previous = consumed;
        consumed += count as u64;
        report.scanned_bytes += count as u64;

        let mut window = Vec::with_capacity(tail.len() + count);
        window.extend_from_slice(&tail);
        window.extend_from_slice(&buffer[..count]);
        let base = previous.saturating_sub(tail.len() as u64);
        scan_ascii(&window, base, previous, expression, source, options, report);
        if options.utf16le && report.matches.len() < options.max_matches {
            scan_utf16le(&window, base, previous, expression, source, options, report);
        }
        if report.matches.len() >= options.max_matches {
            report.truncated = true;
            break;
        }
        let keep = window.len().min(OVERLAP);
        tail.clear();
        tail.extend_from_slice(&window[window.len() - keep..]);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn scan_ascii(
    bytes: &[u8],
    base: u64,
    previous: u64,
    expression: &Regex,
    source: &ScanSource,
    options: ScanOptions,
    report: &mut HuntReport,
) {
    for found in expression.find_iter(bytes) {
        let end = base + found.end() as u64;
        if end <= previous {
            continue;
        }
        let start = found.start().saturating_sub(options.context);
        let stop = (found.end() + options.context).min(bytes.len());
        report.matches.push(HuntMatch {
            source: source.source.to_string(),
            partition: source.partition,
            path: source.path.clone(),
            offset: base + found.start() as u64,
            encoding: "ascii/utf-8".to_string(),
            matched: printable(&bytes[found.start()..found.end()]),
            context: printable(&bytes[start..stop]),
        });
        if report.matches.len() >= options.max_matches {
            return;
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn scan_utf16le(
    bytes: &[u8],
    base: u64,
    previous: u64,
    expression: &Regex,
    source: &ScanSource,
    options: ScanOptions,
    report: &mut HuntReport,
) {
    for alignment in 0..=1 {
        if bytes.len() <= alignment + 1 {
            continue;
        }
        let pairs = (bytes.len() - alignment) / 2;
        let mut collapsed = Vec::with_capacity(pairs);
        for index in 0..pairs {
            let at = alignment + index * 2;
            let low = bytes[at];
            let high = bytes[at + 1];
            collapsed.push(if high == 0 && is_searchable(low) {
                low
            } else {
                0
            });
        }
        for found in expression.find_iter(&collapsed) {
            let byte_start = alignment + found.start() * 2;
            let byte_end = alignment + found.end() * 2;
            let end = base + byte_end as u64;
            if end <= previous {
                continue;
            }
            let start = found.start().saturating_sub(options.context);
            let stop = (found.end() + options.context).min(collapsed.len());
            report.matches.push(HuntMatch {
                source: source.source.to_string(),
                partition: source.partition,
                path: source.path.clone(),
                offset: base + byte_start as u64,
                encoding: "utf-16le".to_string(),
                matched: printable(&collapsed[found.start()..found.end()]),
                context: printable(&collapsed[start..stop]),
            });
            if report.matches.len() >= options.max_matches {
                return;
            }
        }
    }
}

fn is_searchable(byte: u8) -> bool {
    byte == b'\t' || byte == b'\r' || byte == b'\n' || (0x20..=0x7e).contains(&byte)
}

fn printable(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| {
            if (0x20..=0x7e).contains(byte) {
                char::from(*byte)
            } else if matches!(*byte, b'\t' | b'\r' | b'\n') {
                ' '
            } else {
                '.'
            }
        })
        .collect::<String>()
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::{HuntReport, ScanOptions, ScanSource, scan_reader};
    use regex::bytes::Regex;

    fn options() -> ScanOptions {
        ScanOptions {
            max_matches: 10,
            context: 8,
            utf16le: true,
        }
    }

    #[test]
    fn finds_ascii_and_utf16le_flags_with_offsets() {
        let mut data = b"xxxx DFC{ascii} yyyy ".to_vec();
        let utf16_start = data.len() as u64;
        for unit in "DFC{wide}".encode_utf16() {
            data.extend_from_slice(&unit.to_le_bytes());
        }
        let expression = Regex::new(r"DFC\{[^}]+\}").unwrap();
        let mut report = HuntReport::new(expression.as_str(), "raw");
        scan_reader(
            &data[..],
            &expression,
            &ScanSource {
                source: "raw",
                partition: None,
                path: None,
            },
            options(),
            &mut report,
        )
        .unwrap();
        assert_eq!(report.matches.len(), 2);
        assert_eq!(report.matches[0].offset, 5);
        assert_eq!(report.matches[1].offset, utf16_start);
        assert_eq!(report.matches[1].encoding, "utf-16le");
    }

    #[test]
    fn caps_results_for_hostile_or_overbroad_patterns() {
        let expression = Regex::new("A").unwrap();
        let mut report = HuntReport::new("A", "raw");
        scan_reader(
            &b"AAAA"[..],
            &expression,
            &ScanSource {
                source: "raw",
                partition: None,
                path: None,
            },
            ScanOptions {
                max_matches: 2,
                context: 0,
                utf16le: false,
            },
            &mut report,
        )
        .unwrap();
        assert_eq!(report.matches.len(), 2);
        assert!(report.truncated);
    }
}
