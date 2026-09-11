use std::io::Read;

use anyhow::{Context, Result};
use serde::Serialize;

const CHUNK_SIZE: usize = 1024 * 1024;

struct Signature {
    kind: &'static str,
    extension: &'static str,
    magic: &'static [u8],
}

const SIGNATURES: &[Signature] = &[
    Signature {
        kind: "png",
        extension: "png",
        magic: b"\x89PNG\r\n\x1a\n",
    },
    Signature {
        kind: "jpeg",
        extension: "jpg",
        magic: b"\xff\xd8\xff",
    },
    Signature {
        kind: "gif87a",
        extension: "gif",
        magic: b"GIF87a",
    },
    Signature {
        kind: "gif89a",
        extension: "gif",
        magic: b"GIF89a",
    },
    Signature {
        kind: "pdf",
        extension: "pdf",
        magic: b"%PDF-",
    },
    Signature {
        kind: "zip",
        extension: "zip",
        magic: b"PK\x03\x04",
    },
    Signature {
        kind: "7z",
        extension: "7z",
        magic: b"7z\xbc\xaf\x27\x1c",
    },
    Signature {
        kind: "rar",
        extension: "rar",
        magic: b"Rar!\x1a\x07",
    },
    Signature {
        kind: "gzip",
        extension: "gz",
        magic: b"\x1f\x8b\x08",
    },
    Signature {
        kind: "pe",
        extension: "exe",
        magic: b"MZ",
    },
    Signature {
        kind: "elf",
        extension: "elf",
        magic: b"\x7fELF",
    },
    Signature {
        kind: "sqlite",
        extension: "sqlite",
        magic: b"SQLite format 3\0",
    },
    Signature {
        kind: "pcap-le",
        extension: "pcap",
        magic: b"\xd4\xc3\xb2\xa1",
    },
    Signature {
        kind: "pcap-be",
        extension: "pcap",
        magic: b"\xa1\xb2\xc3\xd4",
    },
    Signature {
        kind: "windows-registry-hive",
        extension: "hive",
        magic: b"regf",
    },
];

#[derive(Debug, Clone, Serialize)]
pub struct CarveCandidate {
    pub offset: u64,
    pub kind: String,
    pub suggested_extension: String,
    pub header_hex: String,
}

#[derive(Debug, Serialize)]
pub struct CarveReport {
    pub image: String,
    pub virtual_size: u64,
    pub scanned_bytes: u64,
    pub truncated: bool,
    pub candidates: Vec<CarveCandidate>,
}

pub fn scan_signatures(
    mut reader: impl Read,
    image: &str,
    virtual_size: u64,
    type_filter: Option<&str>,
    max_candidates: usize,
) -> Result<CarveReport> {
    let selected: Vec<&Signature> = SIGNATURES
        .iter()
        .filter(|signature| {
            type_filter.is_none_or(|filter| {
                filter.eq_ignore_ascii_case(signature.kind)
                    || filter.eq_ignore_ascii_case(signature.extension)
            })
        })
        .collect();
    let mut report = CarveReport {
        image: image.to_string(),
        virtual_size,
        scanned_bytes: 0,
        truncated: false,
        candidates: Vec::new(),
    };
    if selected.is_empty() {
        return Ok(report);
    }

    let overlap = selected
        .iter()
        .map(|signature| signature.magic.len())
        .max()
        .unwrap_or(1)
        .saturating_sub(1);
    let mut buffer = vec![0_u8; CHUNK_SIZE];
    let mut tail = Vec::new();
    let mut consumed = 0_u64;
    loop {
        let read = reader
            .read(&mut buffer)
            .context("cannot read decoded image while carving")?;
        if read == 0 {
            break;
        }
        let previous = consumed;
        consumed += read as u64;
        report.scanned_bytes += read as u64;
        let mut window = Vec::with_capacity(tail.len() + read);
        window.extend_from_slice(&tail);
        window.extend_from_slice(&buffer[..read]);
        let base = previous.saturating_sub(tail.len() as u64);

        for signature in &selected {
            for index in find_all(&window, signature.magic) {
                let offset = base + index as u64;
                if offset + signature.magic.len() as u64 <= previous {
                    continue;
                }
                let header_end = (index + 16).min(window.len());
                report.candidates.push(CarveCandidate {
                    offset,
                    kind: signature.kind.to_string(),
                    suggested_extension: signature.extension.to_string(),
                    header_hex: hex(&window[index..header_end]),
                });
                if report.candidates.len() >= max_candidates {
                    report.truncated = true;
                    report.candidates.sort_by_key(|candidate| candidate.offset);
                    return Ok(report);
                }
            }
        }
        let keep = overlap.min(window.len());
        tail.clear();
        tail.extend_from_slice(&window[window.len() - keep..]);
    }
    report.candidates.sort_by_key(|candidate| candidate.offset);
    Ok(report)
}

fn find_all(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return Vec::new();
    }
    haystack
        .windows(needle.len())
        .enumerate()
        .filter_map(|(index, window)| (window == needle).then_some(index))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::scan_signatures;

    #[test]
    fn finds_and_orders_embedded_headers() {
        let mut bytes = [0_u8; 128];
        bytes[80..85].copy_from_slice(b"%PDF-");
        bytes[10..18].copy_from_slice(b"\x89PNG\r\n\x1a\n");
        let report = scan_signatures(&bytes[..], "fixture", 128, None, 10).unwrap();
        assert_eq!(report.candidates.len(), 2);
        assert_eq!(report.candidates[0].offset, 10);
        assert_eq!(report.candidates[0].kind, "png");
        assert_eq!(report.candidates[1].offset, 80);
    }

    #[test]
    fn filters_types_and_caps_candidates() {
        let bytes = b"MZ....MZ....MZ";
        let report = scan_signatures(&bytes[..], "fixture", 14, Some("exe"), 2).unwrap();
        assert_eq!(report.candidates.len(), 2);
        assert!(report.truncated);
        assert!(report.candidates.iter().all(|item| item.kind == "pe"));
    }
}
