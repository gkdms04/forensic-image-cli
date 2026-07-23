use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

pub trait ReadSeek: Read + Seek + Send {}
impl<T: Read + Seek + Send> ReadSeek for T {}

pub type ImageReader = Box<dyn ReadSeek>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageKind {
    Raw,
    Ewf,
    Vmdk,
}

impl std::fmt::Display for ImageKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Raw => formatter.write_str("RAW"),
            Self::Ewf => formatter.write_str("E01/EWF"),
            Self::Vmdk => formatter.write_str("VMDK"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ImageFactory {
    path: PathBuf,
    kind: ImageKind,
}

pub struct OpenedImage {
    pub reader: ImageReader,
    pub kind: ImageKind,
    pub virtual_size: u64,
}

impl ImageFactory {
    pub fn detect(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let metadata = path
            .metadata()
            .with_context(|| format!("cannot inspect image '{}'", path.display()))?;
        if !metadata.is_file() {
            bail!("image is not a regular file: '{}'", path.display());
        }

        let mut file =
            File::open(path).with_context(|| format!("cannot open image '{}'", path.display()))?;
        let mut header = [0_u8; 512];
        let read = file
            .read(&mut header)
            .with_context(|| format!("cannot read image header '{}'", path.display()))?;
        let header = &header[..read];
        let extension = path
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();

        let is_ewf = header.starts_with(&ewf::EVF_SIGNATURE)
            || header.starts_with(b"EVF2\r\n\x81\0")
            || matches!(extension.as_str(), "e01" | "ex01" | "l01" | "lx01");
        let is_vmdk = header.starts_with(b"KDMV")
            || header.starts_with(b"# Disk DescriptorFile")
            || extension == "vmdk";
        let kind = if is_ewf {
            ImageKind::Ewf
        } else if is_vmdk {
            ImageKind::Vmdk
        } else {
            ImageKind::Raw
        };

        Ok(Self {
            path: path.to_path_buf(),
            kind,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn kind(&self) -> ImageKind {
        self.kind
    }

    pub fn open(&self) -> Result<OpenedImage> {
        let mut reader: ImageReader = match self.kind {
            ImageKind::Raw => Box::new(
                File::open(&self.path)
                    .with_context(|| format!("cannot open raw image '{}'", self.path.display()))?,
            ),
            ImageKind::Ewf => Box::new(
                ewf::EwfReader::open(&self.path)
                    .with_context(|| format!("cannot decode EWF '{}'", self.path.display()))?,
            ),
            ImageKind::Vmdk => Box::new(
                vmdk::VmdkFileReader::open_path(&self.path)
                    .with_context(|| format!("cannot decode VMDK '{}'", self.path.display()))?,
            ),
        };
        let virtual_size = reader
            .seek(SeekFrom::End(0))
            .context("cannot determine virtual image size")?;
        reader
            .seek(SeekFrom::Start(0))
            .context("cannot rewind image")?;
        Ok(OpenedImage {
            reader,
            kind: self.kind,
            virtual_size,
        })
    }
}

pub struct WindowReader<R> {
    inner: R,
    base: u64,
    len: u64,
    position: u64,
}

impl<R> WindowReader<R> {
    pub fn new(inner: R, base: u64, len: u64) -> Self {
        Self {
            inner,
            base,
            len,
            position: 0,
        }
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl<R: Read + Seek> Read for WindowReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if self.position >= self.len {
            return Ok(0);
        }
        let remaining = self.len - self.position;
        let requested = remaining.min(buffer.len() as u64) as usize;
        self.inner
            .seek(SeekFrom::Start(self.base + self.position))?;
        let read = self.inner.read(&mut buffer[..requested])?;
        self.position += read as u64;
        Ok(read)
    }
}

impl<R: Read + Seek> Seek for WindowReader<R> {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        let next = match position {
            SeekFrom::Start(offset) => i128::from(offset),
            SeekFrom::End(offset) => i128::from(self.len) + i128::from(offset),
            SeekFrom::Current(offset) => i128::from(self.position) + i128::from(offset),
        };
        if next < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek before partition start",
            ));
        }
        self.position = u64::try_from(next).unwrap_or(u64::MAX);
        Ok(self.position)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read, Seek, SeekFrom};

    use super::WindowReader;

    #[test]
    fn window_reader_never_reads_outside_its_range() {
        let data: Vec<u8> = (0..32).collect();
        let mut reader = WindowReader::new(Cursor::new(data), 10, 5);
        let mut output = Vec::new();
        reader.read_to_end(&mut output).unwrap();
        assert_eq!(output, vec![10, 11, 12, 13, 14]);
    }

    #[test]
    fn window_reader_supports_relative_seek() {
        let data: Vec<u8> = (0..32).collect();
        let mut reader = WindowReader::new(Cursor::new(data), 10, 10);
        reader.seek(SeekFrom::End(-2)).unwrap();
        let mut output = [0_u8; 2];
        reader.read_exact(&mut output).unwrap();
        assert_eq!(output, [18, 19]);
    }
}
