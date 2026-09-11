use std::io::Read;

use anyhow::{Context, Result, bail};
use forensic_vfs::{FileId, FileSystem, StreamId};
use md5::Md5;
use serde::Serialize;
use sha1::Sha1;
use sha2::{Digest, Sha256};

const BUFFER_SIZE: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct Hashes {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
}

struct Hashers {
    md5: Md5,
    sha1: Sha1,
    sha256: Sha256,
}

impl Hashers {
    fn new() -> Self {
        Self {
            md5: Md5::new(),
            sha1: Sha1::new(),
            sha256: Sha256::new(),
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        self.md5.update(bytes);
        self.sha1.update(bytes);
        self.sha256.update(bytes);
    }

    fn finish(self) -> Hashes {
        Hashes {
            md5: format!("{:x}", self.md5.finalize()),
            sha1: format!("{:x}", self.sha1.finalize()),
            sha256: format!("{:x}", self.sha256.finalize()),
        }
    }
}

pub fn hash_reader(mut reader: impl Read) -> Result<(u64, Hashes)> {
    let mut buffer = vec![0_u8; BUFFER_SIZE];
    let mut total = 0_u64;
    let mut hashers = Hashers::new();
    loop {
        let read = reader
            .read(&mut buffer)
            .context("cannot read data to hash")?;
        if read == 0 {
            break;
        }
        hashers.update(&buffer[..read]);
        total += read as u64;
    }
    Ok((total, hashers.finish()))
}

pub fn hash_node(filesystem: &dyn FileSystem, id: FileId, size: u64) -> Result<Hashes> {
    let mut buffer = vec![0_u8; BUFFER_SIZE];
    let mut offset = 0_u64;
    let mut hashers = Hashers::new();
    while offset < size {
        let wanted = (size - offset).min(BUFFER_SIZE as u64) as usize;
        let read = filesystem
            .read_at(id, StreamId::Default, offset, &mut buffer[..wanted])
            .with_context(|| format!("cannot read file at byte offset {offset}"))?;
        if read == 0 {
            bail!("unexpected end of file at byte offset {offset} of {size}");
        }
        hashers.update(&buffer[..read]);
        offset += read as u64;
    }
    Ok(hashers.finish())
}

#[cfg(test)]
mod tests {
    use super::hash_reader;

    #[test]
    fn computes_all_common_ctf_hashes_in_one_pass() {
        let (size, hashes) = hash_reader(&b"abc"[..]).unwrap();
        assert_eq!(size, 3);
        assert_eq!(hashes.md5, "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(hashes.sha1, "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            hashes.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
