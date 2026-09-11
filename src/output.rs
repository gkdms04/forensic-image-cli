use forensic_vfs::{Allocation, MacbTimes, NodeKind, TimeStamp};
use serde::Serialize;

use crate::digest::Hashes;
use crate::partition::Partition;

/// How command results are rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
}

impl OutputFormat {
    pub fn from_json_flag(json: bool) -> Self {
        if json { Self::Json } else { Self::Text }
    }
}

/// Serialize a report to stdout as pretty JSON.
pub fn print_json<T: Serialize>(value: &T) -> anyhow::Result<()> {
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer_pretty(&mut stdout, value)?;
    use std::io::Write;
    stdout.write_all(b"\n")?;
    Ok(())
}

pub fn node_kind_str(kind: NodeKind) -> &'static str {
    match kind {
        NodeKind::File => "file",
        NodeKind::Dir => "dir",
        NodeKind::Symlink => "symlink",
        NodeKind::Device => "device",
        _ => "other",
    }
}

pub fn allocation_str(allocated: Allocation) -> &'static str {
    match allocated {
        Allocation::Allocated => "allocated",
        Allocation::Deleted => "deleted",
        Allocation::Orphan => "orphan",
        _ => "unknown",
    }
}

/// Render a timestamp as RFC 3339 UTC with nanosecond precision, or `None` when the
/// filesystem does not carry that time (distinct from an epoch-zero value).
pub fn format_ts(ts: Option<TimeStamp>) -> Option<String> {
    ts.map(|value| rfc3339_utc(value.unix_nanos))
}

/// Whole seconds since the Unix epoch, or 0 when absent (bodyfile convention).
pub fn ts_unix_secs(ts: Option<TimeStamp>) -> i64 {
    ts.map(|value| value.unix_nanos.div_euclid(1_000_000_000) as i64)
        .unwrap_or(0)
}

fn rfc3339_utc(unix_nanos: i128) -> String {
    let secs = unix_nanos.div_euclid(1_000_000_000) as i64;
    let days = secs.div_euclid(86_400);
    let time_of_day = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = time_of_day / 3_600;
    let minute = (time_of_day % 3_600) / 60;
    let second = time_of_day % 60;
    let nanos = unix_nanos.rem_euclid(1_000_000_000);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{nanos:09}Z")
}

/// Convert days since the Unix epoch to a civil (year, month, day). Howard
/// Hinnant's `civil_from_days`, which avoids a calendar/time dependency.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let year = if month <= 2 { year + 1 } else { year };
    (year, month, day)
}

/// The four MAC(B) times as RFC 3339 UTC strings, `null` when absent.
#[derive(Debug, Serialize)]
pub struct TimesReport {
    pub modified: Option<String>,
    pub accessed: Option<String>,
    pub changed: Option<String>,
    pub born: Option<String>,
}

impl From<&MacbTimes> for TimesReport {
    fn from(times: &MacbTimes) -> Self {
        Self {
            modified: format_ts(times.modified),
            accessed: format_ts(times.accessed),
            changed: format_ts(times.changed),
            born: format_ts(times.born),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct InfoReport {
    pub path: String,
    pub container: String,
    pub host_size: u64,
    pub virtual_size: u64,
    pub partition_scheme: String,
    pub partition_count: usize,
    pub partitions: Vec<InfoPartition>,
}

#[derive(Debug, Serialize)]
pub struct InfoPartition {
    pub number: usize,
    pub filesystem: String,
    pub byte_offset: u64,
    pub name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PartitionRow<'a> {
    #[serde(flatten)]
    pub partition: &'a Partition,
    pub filesystem: String,
    pub byte_offset: u64,
    pub byte_len: u64,
}

#[derive(Debug, Serialize)]
pub struct TreeReport {
    pub partition: usize,
    pub filesystem: String,
    pub name: Option<String>,
    pub entries: Vec<TreeNode>,
}

#[derive(Debug, Serialize)]
pub struct TreeNode {
    pub path: String,
    pub name: String,
    pub kind: String,
    pub size: u64,
    pub depth: usize,
}

#[derive(Debug, Serialize)]
pub struct FindMatch {
    pub partition: usize,
    pub kind: String,
    pub size: u64,
    pub path: String,
}

#[derive(Debug, Serialize)]
pub struct ExtractReport {
    pub extracted: String,
    pub image: String,
    pub partition: usize,
    pub filesystem: String,
    pub internal_path: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Serialize)]
pub struct HashReport {
    pub source: String,
    pub image: String,
    pub partition: Option<usize>,
    pub internal_path: Option<String>,
    pub size: u64,
    #[serde(flatten)]
    pub hashes: Hashes,
}

#[derive(Debug, Serialize)]
pub struct StatReport {
    pub partition: usize,
    pub path: String,
    pub ino: u64,
    pub kind: String,
    pub allocated: String,
    pub size: u64,
    pub nlink: u32,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub mode: Option<u32>,
    pub mode_octal: Option<String>,
    pub times: TimesReport,
}

#[derive(Debug, Serialize)]
pub struct TimelineRow {
    pub partition: usize,
    pub path: String,
    pub kind: String,
    pub size: u64,
    pub modified: Option<String>,
    pub accessed: Option<String>,
    pub changed: Option<String>,
    pub born: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DeletedRow {
    pub partition: usize,
    pub ino: u64,
    pub name: Option<String>,
    pub kind: String,
    pub allocated: String,
    pub size: u64,
    pub modified: Option<String>,
    pub accessed: Option<String>,
    pub changed: Option<String>,
    pub born: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::{civil_from_days, format_ts, rfc3339_utc, ts_unix_secs};
    use forensic_vfs::{TimeResolution, TimeSource, TimeStamp};

    fn ts(unix_nanos: i128) -> TimeStamp {
        TimeStamp {
            unix_nanos,
            source: TimeSource::Unspecified,
            resolution: TimeResolution::Nanos,
        }
    }

    #[test]
    fn epoch_zero_is_unix_start() {
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00.000000000Z");
        assert_eq!(civil_from_days(0), (1970, 1, 1));
    }

    #[test]
    fn formats_a_known_2026_instant() {
        // 2026-07-24T02:15:03Z == 1784859303 seconds since the epoch.
        let nanos = 1_784_859_303_i128 * 1_000_000_000;
        assert_eq!(rfc3339_utc(nanos), "2026-07-24T02:15:03.000000000Z");
        assert_eq!(
            format_ts(Some(ts(nanos))).as_deref(),
            Some("2026-07-24T02:15:03.000000000Z")
        );
    }

    #[test]
    fn handles_leap_day() {
        // 2024-02-29T00:00:00Z == 1709164800.
        assert_eq!(
            rfc3339_utc(1_709_164_800_i128 * 1_000_000_000),
            "2024-02-29T00:00:00.000000000Z"
        );
    }

    #[test]
    fn preserves_nanoseconds_used_by_metadata_hiding_challenges() {
        assert_eq!(
            rfc3339_utc(1_707_592_170_000_016_160),
            "2024-02-10T19:09:30.000016160Z"
        );
    }

    #[test]
    fn absent_time_is_none_and_zero() {
        assert_eq!(format_ts(None), None);
        assert_eq!(ts_unix_secs(None), 0);
        assert_eq!(ts_unix_secs(Some(ts(5_000_000_000))), 5);
    }
}
