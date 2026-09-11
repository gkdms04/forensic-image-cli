use std::time::{SystemTime, UNIX_EPOCH};

use forensic_vfs::{FileSystem, NodeKind, StreamId, TimeStamp};
use serde::Serialize;

use crate::digest::Hashes;
use crate::filesystem::WalkEntry;

#[derive(Debug, Serialize)]
pub struct TriageReport {
    pub image: TriageImage,
    pub partitions: Vec<TriagePartition>,
    pub summary: TriageSummary,
    pub findings_truncated: bool,
    pub findings: Vec<TriageFinding>,
    pub next_steps: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct TriageImage {
    pub path: String,
    pub container: String,
    pub host_size: u64,
    pub virtual_size: u64,
    pub virtual_hashes: Option<Hashes>,
}

#[derive(Debug, Serialize)]
pub struct TriagePartition {
    pub number: usize,
    pub filesystem: String,
    pub byte_offset: u64,
    pub byte_len: u64,
    pub name: Option<String>,
}

#[derive(Debug, Default, Serialize)]
pub struct TriageSummary {
    pub files: u64,
    pub directories: u64,
    pub logical_file_bytes: u64,
    pub deleted_entries: u64,
    pub recoverable_deleted_files: u64,
    pub suspicious_findings: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TriageFinding {
    pub severity: String,
    pub kind: String,
    pub partition: usize,
    pub path: Option<String>,
    pub detail: String,
}

pub struct TriageCollector {
    pub summary: TriageSummary,
    pub findings: Vec<TriageFinding>,
    pub truncated: bool,
    max_findings: usize,
    now_secs: i128,
}

impl TriageCollector {
    pub fn new(max_findings: usize) -> Self {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| i128::from(duration.as_secs()))
            .unwrap_or(0);
        Self {
            summary: TriageSummary::default(),
            findings: Vec::new(),
            truncated: false,
            max_findings,
            now_secs,
        }
    }

    pub fn inspect_entry(
        &mut self,
        partition: usize,
        filesystem: &dyn FileSystem,
        entry: &WalkEntry,
    ) {
        match entry.kind {
            NodeKind::File => {
                self.summary.files += 1;
                self.summary.logical_file_bytes =
                    self.summary.logical_file_bytes.saturating_add(entry.size);
            }
            NodeKind::Dir => self.summary.directories += 1,
            _ => {}
        }

        let lower = entry.path.to_ascii_lowercase();
        if let Some(keyword) = suspicious_keyword(&lower) {
            self.push(TriageFinding {
                severity: "medium".to_string(),
                kind: "suspicious_path".to_string(),
                partition,
                path: Some(entry.path.clone()),
                detail: format!("path contains CTF-relevant keyword '{keyword}'"),
            });
        }
        if entry
            .path
            .split('/')
            .any(|part| part.starts_with('.') && part.len() > 1)
        {
            self.push(TriageFinding {
                severity: "low".to_string(),
                kind: "hidden_path".to_string(),
                partition,
                path: Some(entry.path.clone()),
                detail: "path contains a dot-prefixed component".to_string(),
            });
        }
        if entry.kind == NodeKind::File {
            self.inspect_signature(partition, filesystem, entry);
        }
        self.inspect_times(partition, entry);
    }

    pub fn note_deleted(
        &mut self,
        partition: usize,
        ino: u64,
        name: Option<&str>,
        size: u64,
        recoverable: bool,
    ) {
        self.summary.deleted_entries += 1;
        if recoverable {
            self.summary.recoverable_deleted_files += 1;
        }
        self.push(TriageFinding {
            severity: if recoverable { "high" } else { "medium" }.to_string(),
            kind: "deleted_entry".to_string(),
            partition,
            path: name.map(str::to_string),
            detail: format!(
                "inode/MFT {ino}, {size} bytes, {}",
                if recoverable {
                    "readable with fimg recover"
                } else {
                    "metadata only"
                }
            ),
        });
    }

    pub fn note_partition_issue(&mut self, partition: usize, kind: &str, detail: String) {
        self.push(TriageFinding {
            severity: "high".to_string(),
            kind: kind.to_string(),
            partition,
            path: None,
            detail,
        });
    }

    fn inspect_signature(
        &mut self,
        partition: usize,
        filesystem: &dyn FileSystem,
        entry: &WalkEntry,
    ) {
        if entry.size == 0 {
            return;
        }
        let mut header = [0_u8; 32];
        let wanted = entry.size.min(header.len() as u64) as usize;
        let Ok(read) = filesystem.read_at(entry.id, StreamId::Default, 0, &mut header[..wanted])
        else {
            return;
        };
        let Some(kind) = signature(&header[..read]) else {
            return;
        };
        let extension = entry
            .name
            .rsplit_once('.')
            .map(|(_, value)| value.to_ascii_lowercase());
        match extension.as_deref() {
            Some(ext) if extension_matches(kind, ext) => {}
            Some(ext) if known_extension(ext) => self.push(TriageFinding {
                severity: "high".to_string(),
                kind: "signature_mismatch".to_string(),
                partition,
                path: Some(entry.path.clone()),
                detail: format!("extension .{ext} does not match detected {kind}"),
            }),
            None => self.push(TriageFinding {
                severity: "medium".to_string(),
                kind: "extensionless_known_file".to_string(),
                partition,
                path: Some(entry.path.clone()),
                detail: format!("no extension but content is {kind}"),
            }),
            _ => {}
        }
        if has_double_extension(&entry.name) {
            self.push(TriageFinding {
                severity: "medium".to_string(),
                kind: "double_extension".to_string(),
                partition,
                path: Some(entry.path.clone()),
                detail: "filename has multiple known extensions".to_string(),
            });
        }
    }

    fn inspect_times(&mut self, partition: usize, entry: &WalkEntry) {
        for (label, value) in [
            ("modified", entry.times.modified),
            ("accessed", entry.times.accessed),
            ("changed", entry.times.changed),
            ("born", entry.times.born),
        ] {
            let Some(timestamp) = value else { continue };
            let seconds = timestamp.unix_nanos.div_euclid(1_000_000_000);
            let nanos = timestamp.unix_nanos.rem_euclid(1_000_000_000);
            if seconds > self.now_secs + 86_400 {
                self.push(TriageFinding {
                    severity: "high".to_string(),
                    kind: "future_timestamp".to_string(),
                    partition,
                    path: Some(entry.path.clone()),
                    detail: format!("{label} timestamp is in the future ({seconds}.{nanos:09})"),
                });
            } else if nanos != 0 && nanos < 1_000_000 {
                self.push(TriageFinding {
                    severity: "medium".to_string(),
                    kind: "timestamp_nanosecond_anomaly".to_string(),
                    partition,
                    path: Some(entry.path.clone()),
                    detail: format!(
                        "{label} has unusually small non-zero nanoseconds ({nanos:09}); inspect raw metadata"
                    ),
                });
            }
        }
    }

    fn push(&mut self, finding: TriageFinding) {
        self.summary.suspicious_findings += 1;
        if self.findings.len() < self.max_findings {
            self.findings.push(finding);
        } else {
            self.truncated = true;
        }
    }
}

fn suspicious_keyword(path: &str) -> Option<&'static str> {
    [
        "flag",
        "secret",
        "password",
        "passwd",
        "credential",
        "recovery",
        "bitlocker",
        "backup",
        "deleted",
        "hidden",
        "private",
        "wallet",
        "key",
    ]
    .into_iter()
    .find(|keyword| path.contains(keyword))
}

fn signature(bytes: &[u8]) -> Option<&'static str> {
    let signatures: &[(&[u8], &str)] = &[
        (b"\x89PNG\r\n\x1a\n", "PNG"),
        (b"\xff\xd8\xff", "JPEG"),
        (b"GIF87a", "GIF"),
        (b"GIF89a", "GIF"),
        (b"%PDF-", "PDF"),
        (b"PK\x03\x04", "ZIP"),
        (b"PK\x05\x06", "ZIP"),
        (b"7z\xbc\xaf\x27\x1c", "7Z"),
        (b"Rar!\x1a\x07", "RAR"),
        (b"\x1f\x8b", "GZIP"),
        (b"MZ", "PE"),
        (b"\x7fELF", "ELF"),
        (b"SQLite format 3\0", "SQLITE"),
    ];
    signatures
        .iter()
        .find_map(|(magic, kind)| bytes.starts_with(magic).then_some(*kind))
        .or_else(|| {
            (bytes.starts_with(&[0xd4, 0xc3, 0xb2, 0xa1])
                || bytes.starts_with(&[0xa1, 0xb2, 0xc3, 0xd4]))
            .then_some("PCAP")
        })
}

fn extension_matches(kind: &str, ext: &str) -> bool {
    match kind {
        "PNG" => ext == "png",
        "JPEG" => matches!(ext, "jpg" | "jpeg" | "jpe"),
        "GIF" => ext == "gif",
        "PDF" => ext == "pdf",
        "ZIP" => matches!(ext, "zip" | "docx" | "xlsx" | "pptx" | "jar" | "apk"),
        "7Z" => ext == "7z",
        "RAR" => ext == "rar",
        "GZIP" => matches!(ext, "gz" | "tgz"),
        "PE" => matches!(ext, "exe" | "dll" | "sys" | "scr"),
        "ELF" => matches!(ext, "elf" | "so" | "bin"),
        "SQLITE" => matches!(ext, "sqlite" | "sqlite3" | "db"),
        "PCAP" => matches!(ext, "pcap" | "cap"),
        _ => false,
    }
}

fn known_extension(ext: &str) -> bool {
    matches!(
        ext,
        "png"
            | "jpg"
            | "jpeg"
            | "gif"
            | "pdf"
            | "zip"
            | "docx"
            | "xlsx"
            | "pptx"
            | "7z"
            | "rar"
            | "gz"
            | "exe"
            | "dll"
            | "sys"
            | "elf"
            | "so"
            | "sqlite"
            | "db"
            | "pcap"
    )
}

fn has_double_extension(name: &str) -> bool {
    let mut parts = name.rsplit('.');
    let Some(last) = parts.next() else {
        return false;
    };
    let Some(previous) = parts.next() else {
        return false;
    };
    known_extension(&last.to_ascii_lowercase()) && known_extension(&previous.to_ascii_lowercase())
}

pub fn raw_timestamp(timestamp: TimeStamp) -> String {
    format!(
        "{}.{:09}",
        timestamp.unix_nanos.div_euclid(1_000_000_000),
        timestamp.unix_nanos.rem_euclid(1_000_000_000)
    )
}

#[cfg(test)]
mod tests {
    use super::{extension_matches, has_double_extension, signature};

    #[test]
    fn recognizes_common_carving_signatures() {
        assert_eq!(signature(b"\x89PNG\r\n\x1a\nrest"), Some("PNG"));
        assert_eq!(signature(b"PK\x03\x04rest"), Some("ZIP"));
        assert_eq!(signature(b"SQLite format 3\0rest"), Some("SQLITE"));
    }

    #[test]
    fn treats_office_documents_as_zip_containers() {
        assert!(extension_matches("ZIP", "docx"));
        assert!(!extension_matches("PE", "jpg"));
        assert!(has_double_extension("invoice.pdf.exe"));
    }
}
