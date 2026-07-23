use std::io::{Read, Seek, SeekFrom};

use anyhow::{Context, Result, bail};
use serde::Serialize;

const MBR_SIGNATURE_OFFSET: usize = 510;
const MBR_ENTRY_OFFSET: usize = 446;
const MBR_ENTRY_SIZE: usize = 16;
const GPT_SIGNATURE: &[u8; 8] = b"EFI PART";
const MAX_GPT_ENTRIES: u32 = 4096;
const MAX_GPT_ENTRY_SIZE: u32 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PartitionScheme {
    Whole,
    Mbr,
    Gpt,
}

impl std::fmt::Display for PartitionScheme {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Whole => formatter.write_str("whole"),
            Self::Mbr => formatter.write_str("MBR"),
            Self::Gpt => formatter.write_str("GPT"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Partition {
    pub number: usize,
    pub scheme: PartitionScheme,
    pub start_lba: u64,
    pub sectors: u64,
    pub sector_size: u64,
    pub type_id: String,
    pub name: Option<String>,
}

impl Partition {
    pub fn byte_offset(&self) -> u64 {
        self.start_lba.saturating_mul(self.sector_size)
    }

    pub fn byte_len(&self) -> u64 {
        self.sectors.saturating_mul(self.sector_size)
    }
}

pub fn read_partitions<R: Read + Seek>(reader: &mut R, image_len: u64) -> Result<Vec<Partition>> {
    let mut sector = [0_u8; 512];
    reader
        .seek(SeekFrom::Start(0))
        .context("cannot seek to master boot record")?;
    if reader.read_exact(&mut sector).is_err() || sector[MBR_SIGNATURE_OFFSET..] != [0x55, 0xaa] {
        return Ok(vec![whole_image(image_len)]);
    }

    for sector_size in [512_u64, 4096_u64] {
        if let Some(partitions) = read_gpt(reader, image_len, sector_size)? {
            return Ok(partitions);
        }
    }

    let partitions = read_mbr(&sector, image_len);
    if partitions.is_empty() {
        Ok(vec![whole_image(image_len)])
    } else {
        Ok(partitions)
    }
}

fn whole_image(image_len: u64) -> Partition {
    Partition {
        number: 0,
        scheme: PartitionScheme::Whole,
        start_lba: 0,
        sectors: image_len.div_ceil(512),
        sector_size: 512,
        type_id: "filesystem".to_string(),
        name: Some("Whole image".to_string()),
    }
}

fn read_mbr(sector: &[u8; 512], image_len: u64) -> Vec<Partition> {
    let mut partitions = Vec::new();
    for index in 0..4 {
        let start = MBR_ENTRY_OFFSET + index * MBR_ENTRY_SIZE;
        let entry = &sector[start..start + MBR_ENTRY_SIZE];
        let partition_type = entry[4];
        let start_lba = u64::from(u32::from_le_bytes(entry[8..12].try_into().unwrap()));
        let sectors = u64::from(u32::from_le_bytes(entry[12..16].try_into().unwrap()));
        if partition_type == 0 || sectors == 0 || partition_type == 0xee {
            continue;
        }
        let byte_offset = start_lba.saturating_mul(512);
        let byte_len = sectors.saturating_mul(512);
        if byte_offset >= image_len || byte_len > image_len.saturating_sub(byte_offset) {
            continue;
        }
        partitions.push(Partition {
            number: index + 1,
            scheme: PartitionScheme::Mbr,
            start_lba,
            sectors,
            sector_size: 512,
            type_id: format!("0x{partition_type:02x}"),
            name: Some(mbr_type_name(partition_type).to_string()),
        });
    }
    partitions
}

fn read_gpt<R: Read + Seek>(
    reader: &mut R,
    image_len: u64,
    sector_size: u64,
) -> Result<Option<Vec<Partition>>> {
    let header_offset = sector_size;
    if header_offset.saturating_add(92) > image_len {
        return Ok(None);
    }
    let mut header = [0_u8; 92];
    reader.seek(SeekFrom::Start(header_offset))?;
    reader.read_exact(&mut header)?;
    if &header[..8] != GPT_SIGNATURE {
        return Ok(None);
    }

    let header_size = le_u32(&header[12..16]);
    if !(92..=sector_size as u32).contains(&header_size) {
        bail!("invalid GPT header size: {header_size}");
    }
    let entries_lba = le_u64(&header[72..80]);
    let entry_count = le_u32(&header[80..84]);
    let entry_size = le_u32(&header[84..88]);
    if entry_count > MAX_GPT_ENTRIES {
        bail!("GPT entry count {entry_count} exceeds safety limit {MAX_GPT_ENTRIES}");
    }
    if !(128..=MAX_GPT_ENTRY_SIZE).contains(&entry_size) || entry_size % 8 != 0 {
        bail!("invalid GPT entry size: {entry_size}");
    }

    let table_offset = entries_lba
        .checked_mul(sector_size)
        .context("GPT partition table offset overflow")?;
    let table_len = u64::from(entry_count)
        .checked_mul(u64::from(entry_size))
        .context("GPT partition table size overflow")?;
    if table_offset > image_len || table_len > image_len.saturating_sub(table_offset) {
        bail!("GPT partition table lies outside the image");
    }

    reader.seek(SeekFrom::Start(table_offset))?;
    let mut partitions = Vec::new();
    let mut entry = vec![0_u8; entry_size as usize];
    for index in 0..entry_count {
        reader.read_exact(&mut entry)?;
        if entry[..16].iter().all(|byte| *byte == 0) {
            continue;
        }
        let first_lba = le_u64(&entry[32..40]);
        let last_lba = le_u64(&entry[40..48]);
        if last_lba < first_lba {
            continue;
        }
        let sectors = last_lba - first_lba + 1;
        let byte_offset = first_lba.saturating_mul(sector_size);
        let byte_len = sectors.saturating_mul(sector_size);
        if byte_offset >= image_len || byte_len > image_len.saturating_sub(byte_offset) {
            continue;
        }
        let name_end = entry.len().min(128);
        let name = decode_utf16_name(&entry[56..name_end]);
        partitions.push(Partition {
            number: index as usize + 1,
            scheme: PartitionScheme::Gpt,
            start_lba: first_lba,
            sectors,
            sector_size,
            type_id: format_guid(&entry[..16]),
            name,
        });
    }

    Ok(Some(partitions))
}

fn le_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().unwrap())
}

fn le_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().unwrap())
}

fn decode_utf16_name(bytes: &[u8]) -> Option<String> {
    let words: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .take_while(|word| *word != 0)
        .collect();
    if words.is_empty() {
        None
    } else {
        let value = String::from_utf16_lossy(&words).trim().to_string();
        (!value.is_empty()).then_some(value)
    }
}

fn format_guid(bytes: &[u8]) -> String {
    let data1 = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let data2 = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
    let data3 = u16::from_le_bytes(bytes[6..8].try_into().unwrap());
    format!(
        "{data1:08x}-{data2:04x}-{data3:04x}-{:02x}{:02x}-{}",
        bytes[8],
        bytes[9],
        bytes[10..16]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

fn mbr_type_name(partition_type: u8) -> &'static str {
    match partition_type {
        0x01 => "FAT12",
        0x04 | 0x06 | 0x0e => "FAT16",
        0x05 | 0x0f => "Extended",
        0x07 => "NTFS/exFAT/HPFS",
        0x0b | 0x0c => "FAT32",
        0x82 => "Linux swap",
        0x83 => "Linux filesystem",
        0xaf => "Apple HFS/HFS+",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::{PartitionScheme, read_partitions};

    #[test]
    fn falls_back_to_whole_image_without_partition_table() {
        let bytes = vec![0_u8; 4096];
        let partitions = read_partitions(&mut Cursor::new(bytes), 4096).unwrap();
        assert_eq!(partitions.len(), 1);
        assert_eq!(partitions[0].scheme, PartitionScheme::Whole);
    }

    #[test]
    fn reads_valid_mbr_primary_partition() {
        let mut bytes = vec![0_u8; 20 * 512];
        bytes[510] = 0x55;
        bytes[511] = 0xaa;
        let entry = &mut bytes[446..462];
        entry[4] = 0x07;
        entry[8..12].copy_from_slice(&1_u32.to_le_bytes());
        entry[12..16].copy_from_slice(&10_u32.to_le_bytes());
        let partitions = read_partitions(&mut Cursor::new(bytes), 20 * 512).unwrap();
        assert_eq!(partitions.len(), 1);
        assert_eq!(partitions[0].scheme, PartitionScheme::Mbr);
        assert_eq!(partitions[0].start_lba, 1);
        assert_eq!(partitions[0].sectors, 10);
    }

    #[test]
    fn reads_gpt_partition_name_and_bounds() {
        let mut bytes = vec![0_u8; 100 * 512];
        bytes[510] = 0x55;
        bytes[511] = 0xaa;
        let header = &mut bytes[512..1024];
        header[..8].copy_from_slice(b"EFI PART");
        header[8..12].copy_from_slice(&0x0001_0000_u32.to_le_bytes());
        header[12..16].copy_from_slice(&92_u32.to_le_bytes());
        header[72..80].copy_from_slice(&2_u64.to_le_bytes());
        header[80..84].copy_from_slice(&1_u32.to_le_bytes());
        header[84..88].copy_from_slice(&128_u32.to_le_bytes());
        let entry = &mut bytes[1024..1152];
        entry[..16].copy_from_slice(&[1_u8; 16]);
        entry[32..40].copy_from_slice(&10_u64.to_le_bytes());
        entry[40..48].copy_from_slice(&19_u64.to_le_bytes());
        for (index, word) in "Evidence".encode_utf16().enumerate() {
            let offset = 56 + index * 2;
            entry[offset..offset + 2].copy_from_slice(&word.to_le_bytes());
        }
        let partitions = read_partitions(&mut Cursor::new(bytes), 100 * 512).unwrap();
        assert_eq!(partitions.len(), 1);
        assert_eq!(partitions[0].scheme, PartitionScheme::Gpt);
        assert_eq!(partitions[0].name.as_deref(), Some("Evidence"));
        assert_eq!(partitions[0].byte_offset(), 10 * 512);
    }
}
