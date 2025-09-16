use std::{
    array::TryFromSliceError,
    fmt::Display,
    fs::OpenOptions,
    io::{Error, ErrorKind, Write},
    path::{Path, PathBuf},
};

use crc::{CRC_32_ISO_HDLC, Crc};
type CRC = u32;
type FileID = u32;

use serde::{Deserialize, Serialize};

#[cfg(feature = "bincode")]
pub const HEADER_SIZE: usize = 4 + 8 + 4 + 4 + 8 + 8;
#[cfg(not(feature = "bincode"))]
pub const HEADER_SIZE: usize = 20;

fn log_file_path(file_id: FileID) -> String {
    format!("{file_id:06}.log")
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub struct LogPointer {
    file_id: FileID,
    offset: u64,
    size: u32,
    timestamp: u64,
}

impl LogPointer {
    pub fn new(file_id: FileID, offset: u64, size: u32, timestamp: u64) -> Self {
        LogPointer {
            file_id,
            offset,
            size,
            timestamp,
        }
    }

    pub fn file_id(&self) -> FileID {
        self.file_id
    }

    pub fn offset(&self) -> u64 {
        self.offset
    }

    pub fn size(&self) -> u32 {
        self.size
    }

    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }
    pub fn file_path(&self, path: &str) -> PathBuf {
        let mut path_buf = PathBuf::new();
        path_buf.push(path);
        path_buf.push(log_file_path(self.file_id));
        path_buf
    }
}

#[derive(Serialize, Deserialize)]
struct LogEntryHeader {
    crc: CRC,
    timestamp: u64,
    key_len: u32,
    value_len: u32,
}

#[derive(Serialize, Deserialize)]
pub struct LogEntry {
    header: LogEntryHeader,
    key: Vec<u8>,
    value: Vec<u8>,
}

impl LogEntry {
    pub fn new(key: &[u8], value: &[u8], timestamp: u64) -> Self {
        LogEntry {
            header: LogEntryHeader {
                key_len: key.len() as u32,
                value_len: value.len() as u32,
                timestamp,
                crc: 0,
            },
            key: key.into(),
            value: value.into(),
        }
    }

    pub fn key(&self) -> &[u8] {
        &self.key
    }

    pub fn value(&self) -> &[u8] {
        &self.value
    }

    pub fn timestamp(&self) -> u64 {
        self.header.timestamp
    }

    pub fn key_len(&self) -> u32 {
        self.header.key_len
    }

    pub fn value_len(&self) -> u32 {
        self.header.value_len
    }

    pub fn calculate_crc(&mut self) {
        let crc = Crc::<u32>::new(&CRC_32_ISO_HDLC);
        let bytes = [self.key(), self.value(), &self.timestamp().to_le_bytes()].concat();
        let checksum = crc.checksum(&bytes);
        self.header.crc = checksum;
    }

    pub fn crc(&self) -> CRC {
        self.header.crc
    }

    pub fn serialize(&self) -> Result<Vec<u8>, StorageError> {
        #[cfg(feature = "bincode")]
        {
            Ok(bincode::serialize(&self)?)
        }
        #[cfg(not(feature = "bincode"))]
        {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&self.crc().to_le_bytes());
            bytes.extend_from_slice(&self.key_len().to_le_bytes());
            bytes.extend_from_slice(&self.value_len().to_le_bytes());
            bytes.extend_from_slice(&self.timestamp().to_le_bytes());
            bytes.extend_from_slice(self.key());
            bytes.extend_from_slice(self.value());
            Ok(bytes)
        }
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, StorageError> {
        if bytes.len() < 20 {
            return Err(StorageError::Io(Error::new(
                ErrorKind::InvalidInput,
                "header is 20 bytes",
            )));
        }
        #[cfg(feature = "bincode")]
        {
            Ok(bincode::deserialize(bytes)?)
        }
        #[cfg(not(feature = "bincode"))]
        {
            let crc = u32::from_le_bytes(bytes[0..4].try_into()?);
            let key_len = u32::from_le_bytes(bytes[4..8].try_into()?);
            let value_len = u32::from_le_bytes(bytes[8..12].try_into()?);
            let timestamp = u64::from_le_bytes(bytes[12..20].try_into()?);
            let key = bytes[20..20 + key_len as usize].to_vec();
            let value = bytes[(20 + key_len as usize)..].to_vec();
            Ok(LogEntry {
                header: LogEntryHeader {
                    crc,
                    timestamp,
                    key_len,
                    value_len,
                },
                key,
                value,
            })
        }
    }

    pub fn validate_crc(&self) -> bool {
        let crc = Crc::<u32>::new(&CRC_32_ISO_HDLC);
        let bytes = [self.key(), self.value(), &self.timestamp().to_le_bytes()].concat();
        let checksum = crc.checksum(&bytes);
        checksum == self.crc()
    }

    pub fn size(&self) -> usize {
        HEADER_SIZE + self.key.len() + self.value.len()
    }
}

#[derive(Debug)]
pub enum StorageError<'a> {
    Io(std::io::Error),
    Corruption(&'a str),
    Serialization(&'a str),
}

impl<'a> Display for StorageError<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "IO Error: {e}"),
            Self::Corruption(e) => write!(f, "Corruption: {e}"),
            Self::Serialization(e) => write!(f, "Serialization: {e}"),
        }
    }
}

impl<'a> std::error::Error for StorageError<'a> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl<'a> StorageError<'a> {
    pub fn corruption(e: &'a str) -> StorageError<'a> {
        StorageError::Corruption(e)
    }
    pub fn serialization(e: &'a str) -> StorageError<'a> {
        StorageError::Serialization(e)
    }
}

impl<'a> From<TryFromSliceError> for StorageError<'a> {
    fn from(_: TryFromSliceError) -> Self {
        Self::Serialization("slice error")
    }
}

#[cfg(feature = "bincode")]
impl<'a> From<Box<bincode::ErrorKind>> for StorageError<'a> {
    fn from(_: Box<bincode::ErrorKind>) -> Self {
        StorageError::Serialization("serialization error")
    }
}

impl<'a> From<std::io::Error> for StorageError<'a> {
    fn from(err: std::io::Error) -> Self {
        StorageError::Io(err)
    }
}

pub type Offset = u64;
pub type Size = u64;

struct RotationConfig {
    base_dir: PathBuf,
    max_file_size: Size,
    current_file_id: FileID,
}

impl RotationConfig {
    pub fn increment_file_id(&mut self) -> FileID {
        self.current_file_id += 1;
        self.current_file_id
    }
}

pub struct LogWriter<T>
where
    T: Write + AsRef<[u8]> + Default,
{
    offset: Offset,
    current_file: PathBuf,
    buffer: T,
    rotation_config: Option<RotationConfig>,
}

impl<T> Drop for LogWriter<T>
where
    T: Write + AsRef<[u8]> + Default,
{
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

impl<T> LogWriter<T>
where
    T: Write + AsRef<[u8]> + Default,
{
    pub fn new(path: &Path) -> Result<Self, &'static str> {
        Self::initialise(path, None)
    }

    pub fn with_options(path: &Path, size: Size) -> Result<Self, &'static str> {
        let current_file_id = 0;
        Self::initialise(
            &path.join(log_file_path(current_file_id)),
            Some(RotationConfig {
                max_file_size: size,
                current_file_id,
                base_dir: path.into(),
            }),
        )
    }

    fn initialise(
        current_file: &Path,
        rotation_config: Option<RotationConfig>,
    ) -> Result<Self, &'static str> {
        let this = LogWriter {
            offset: 0,
            current_file: current_file.to_path_buf(),
            buffer: T::default(),
            rotation_config,
        };
        let _ = this.get_current_file()?;
        Ok(this)
    }

    pub fn current_file_id(&self) -> FileID {
        match &self.rotation_config {
            Some(config) => config.current_file_id,
            None => 0,
        }
    }

    pub fn current_offset(&self) -> Offset {
        self.offset
    }

    fn reset_buffer(&mut self) {
        self.buffer = T::default();
        self.offset = 0;
    }

    fn write_to_buffer(&mut self, bytes: &[u8]) -> Result<u64, &'static str> {
        self.buffer
            .write_all(&bytes)
            .map_err(|_| "failed to write")?;

        let offset = self.offset;
        self.offset += bytes.len() as Size;
        Ok(offset)
    }

    pub fn should_rotate(&self, entry: &LogEntry) -> bool {
        match &self.rotation_config {
            Some(rotation_config) => {
                let entry_size = entry.size() as u64;
                self.current_offset() + entry_size > rotation_config.max_file_size
            }
            None => false,
        }
    }

    pub fn rotate(&mut self) -> Result<(), &'static str> {
        if self.rotation_config.is_none() {
            return Err("No rotation config available");
        }

        self.flush()?;

        let rotation_config = self.rotation_config.as_mut().unwrap();
        let new_file_id = rotation_config.increment_file_id();

        let mut new_file_path = rotation_config.base_dir.clone();
        new_file_path.push(log_file_path(new_file_id));

        self.current_file = new_file_path;

        Ok(())
    }

    pub fn append(&mut self, entry: &LogEntry) -> Result<Offset, &'static str> {
        Ok(self.append_with_size(entry)?.0)
    }

    pub fn append_with_size(&mut self, entry: &LogEntry) -> Result<(Offset, Size), &'static str> {
        if self.should_rotate(entry) {
            self.rotate()?;
        }
        let bytes = entry.serialize().map_err(|_| "failed to serialize")?;
        let offset = self.write_to_buffer(&bytes)?;
        Ok((offset, bytes.len() as Size))
    }

    fn get_current_file(&self) -> Result<std::fs::File, &'static str> {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.current_file)
            .map_err(|_| "failed to open file")
    }

    fn write_to_file(&mut self, file: &mut std::fs::File) -> Result<(), &'static str> {
        file.write_all(self.buffer.as_ref())
            .map_err(|_| "writing to file failed")?;
        self.reset_buffer();
        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), &'static str> {
        let mut file = self.get_current_file()?;
        self.write_to_file(&mut file)?;
        Ok(())
    }

    pub fn sync(&mut self) -> Result<(), &'static str> {
        let mut file = self.get_current_file()?;
        self.write_to_file(&mut file)?;
        file.sync_all().map_err(|_| "failed to sync")
    }
}
