use crc::{CRC_32_ISO_HDLC, Crc};
use log::{debug, info};
use serde::{Deserialize, Serialize};
use std::{
    array::TryFromSliceError,
    cell::RefCell,
    collections::{
        HashMap,
        hash_map::{Entry, Iter, Keys},
    },
    fmt::Display,
    fs::{DirEntry, OpenOptions},
    io::{Error, ErrorKind, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

type CRC = u32;
type FileID = u32;
#[cfg(feature = "bincode")]
pub const HEADER_SIZE: usize = 4 + 8 + 4 + 4 + 8 + 8;
#[cfg(not(feature = "bincode"))]
pub const HEADER_SIZE: usize = 20;
pub const ROTATION_FILE_SIZE: Size = 1024 * 1024;

pub type MemoryLogWriter = LogWriter<Vec<u8>>;

pub struct Bitcask {
    path: PathBuf,
    writer: RefCell<MemoryLogWriter>,
    readers: RefCell<HashMap<FileID, LogReader>>,
    memory_index: RefCell<MemIndex>,
}

impl Bitcask {
    pub fn open_with_options(path: &Path, options: BitcaskOptions) -> Result<Self, StorageError> {
        info!("Opening Bitcask at {:?} with options {:?}", path, options);
        Ok(if Self::has_log_files(path)? {
            let (writer, memory_index) = Self::restore(path)?;
            Bitcask {
                path: path.to_path_buf(),
                writer: RefCell::new(writer),
                readers: RefCell::new(HashMap::new()),
                memory_index: RefCell::new(memory_index),
            }
        } else {
            Bitcask {
                path: path.to_path_buf(),
                writer: RefCell::new(MemoryLogWriter::with_options(path, options.size)?),
                readers: RefCell::new(HashMap::new()),
                memory_index: RefCell::new(MemIndex::new()),
            }
        })
    }

    pub fn open(path: &Path) -> Result<Self, StorageError> {
        Self::open_with_options(path, BitcaskOptions::default())
    }

    pub fn put(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        let timestamp = current_timestamp();

        let entry = LogEntry::new(key, value, timestamp);
        let mut writer = self.writer.borrow_mut();
        let offset = writer.append(&entry)?;

        let pointer = LogPointer::new(
            writer.current_file_id(),
            offset,
            entry.size() as u64,
            timestamp,
        );
        self.memory_index.borrow_mut().insert(key.to_vec(), pointer);

        Ok(())
    }

    fn get_entry(&self, pointer: &LogPointer) -> Result<LogEntry, StorageError> {
        self.writer.borrow_mut().flush()?;
        match self.readers.borrow_mut().entry(pointer.file_id()) {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(e) => e.insert(LogReader::new(&pointer.file_path(&self.path))?),
        }
        .read_at(pointer.offset(), pointer.size())
    }

    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(match self.memory_index.borrow().get(key) {
            Some(pointer) => {
                let entry = self.get_entry(pointer)?;
                Some(entry.value().to_vec())
            }
            None => None,
        })
    }

    pub fn delete(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        let mut memory_index = self.memory_index.borrow_mut();
        Ok(match memory_index.get(key) {
            Some(pointer) => {
                let mut entry = self.get_entry(pointer)?;
                let value = entry.value.clone();
                entry.tombstone();
                let offset = self.writer.borrow_mut().append(&entry)?;
                memory_index.delete(key);
                Some(value)
            }
            None => None,
        })
    }

    pub fn sync(&self) -> Result<(), StorageError> {
        self.writer.borrow_mut().sync()
    }

    fn has_log_files(path: &Path) -> Result<bool, StorageError> {
        // Check if any .log files exist
        for entry in std::fs::read_dir(path)? {
            if let Ok(entry) = entry {
                if entry.path().extension() == Some("log".as_ref()) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    fn rebuild(
        path: &Path,
        memory_map: HashMap<Vec<u8>, LogEntry>,
    ) -> Result<(MemoryLogWriter, MemIndex), StorageError> {
        debug!("Rebuilding path {:?}", path);
        let mut writer = MemoryLogWriter::with_options(path, ROTATION_FILE_SIZE)?;
        let mut memory_index = MemIndex::new();
        for (key, entry) in memory_map {
            let offset = writer.append(&entry)?;
            let pointer = LogPointer::new(
                writer.current_file_id(),
                offset,
                entry.size() as u64,
                entry.timestamp(),
            );
            let _ = memory_index.insert(key, pointer);
        }

        Ok((writer, memory_index))
    }

    fn clear_all_files(log_files: &Vec<DirEntry>) -> Result<(), StorageError> {
        for log_file in log_files {
            std::fs::remove_file(log_file.path())?;
        }

        Ok(())
    }

    fn move_files(from: &Path, to: &Path) -> Result<(), StorageError> {
        let log_files: Vec<_> = std::fs::read_dir(from)?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension() == Some("log".as_ref()))
            .collect();

        for log_file in log_files {
            let mut to = to.to_path_buf();
            to.push(log_file.file_name());
            std::fs::rename(&log_file.path(), &to)?;
        }

        Ok(())
    }

    fn restore(path: &Path) -> Result<(MemoryLogWriter, MemIndex), StorageError> {
        info!("Restoring at path {:?}", path);
        let mut memory_map = HashMap::<Vec<u8>, LogEntry>::new();
        let log_files: Vec<_> = std::fs::read_dir(path)?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension() == Some("log".as_ref()))
            .collect();

        for log_file in &log_files {
            let reader = LogReader::new(&log_file.path())?;

            for entry in reader.iter()? {
                if !entry.is_tombstone() {
                    memory_map.remove(entry.key());
                } else {
                    memory_map.insert(entry.key().to_vec(), entry.clone());
                }
            }
        }

        let compact_directory = path.join(".compacting");
        std::fs::create_dir_all(&compact_directory)?;
        let result = Self::rebuild(&compact_directory, memory_map)?;
        Self::clear_all_files(&log_files)?;
        Self::move_files(&compact_directory, path)?;

        Ok(result)
    }

    pub fn compact(&mut self) -> Result<(), StorageError> {
        let _ = Self::restore(&self.path);
        Ok(())
    }
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

pub struct MemIndex {
    index: HashMap<Vec<u8>, LogPointer>,
}

impl MemIndex {
    pub fn new() -> Self {
        MemIndex {
            index: HashMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.index.len()
    }

    pub fn insert(&mut self, key: Vec<u8>, pointer: LogPointer) -> Option<LogPointer> {
        self.index.insert(key, pointer)
    }

    pub fn get(&self, key: &[u8]) -> Option<&LogPointer> {
        self.index.get(key)
    }

    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    pub fn delete(&mut self, key: &[u8]) -> Option<LogPointer> {
        self.index.remove(key)
    }

    pub fn clear(&mut self) {
        self.index.clear();
    }

    pub fn keys(&self) -> Keys<'_, Vec<u8>, LogPointer> {
        self.index.keys()
    }

    pub fn iter(&self) -> Iter<'_, Vec<u8>, LogPointer> {
        self.index.iter()
    }
}

fn log_file_path(file_id: FileID) -> String {
    format!("{file_id:06}.log")
}

type Offset = u64;
type FileOffset = (FileID, Offset);

#[derive(Debug, PartialEq, Clone, Copy)]
pub struct LogPointer {
    file_offset: FileOffset,
    size: u64,
    timestamp: u64,
}

impl LogPointer {
    pub fn new(file_id: FileID, offset: u64, size: u64, timestamp: u64) -> Self {
        LogPointer {
            file_offset: (file_id, offset),
            size,
            timestamp,
        }
    }

    pub fn file_id(&self) -> FileID {
        self.file_offset.0
    }

    pub fn file_offset(&self) -> FileOffset {
        self.file_offset
    }

    pub fn offset(&self) -> Offset {
        self.file_offset.1
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    pub fn file_path(&self, path: &Path) -> PathBuf {
        let mut path_buf = path.to_path_buf();
        path_buf.push(log_file_path(self.file_id()));
        path_buf
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct LogEntryHeader {
    crc: CRC,
    timestamp: u64,
    key_len: u32,
    value_len: u32,
}

impl LogEntryHeader {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, StorageError> {
        let crc = u32::from_le_bytes(bytes[0..4].try_into()?);
        let key_len = u32::from_le_bytes(bytes[4..8].try_into()?);
        let value_len = u32::from_le_bytes(bytes[8..12].try_into()?);
        let timestamp = u64::from_le_bytes(bytes[12..20].try_into()?);

        Ok(LogEntryHeader {
            crc,
            timestamp,
            key_len,
            value_len,
        })
    }
}

#[derive(Serialize, Deserialize, Clone)]
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
            let header = LogEntryHeader::from_bytes(&bytes[0..20])?;
            let key = bytes[20..20 + header.key_len as usize].to_vec();
            let value = bytes[(20 + header.key_len as usize)..].to_vec();
            Ok(LogEntry { header, key, value })
        }
    }

    pub fn deserialize_with_header(
        header: LogEntryHeader,
        bytes: &[u8],
    ) -> Result<Self, StorageError> {
        #[cfg(not(feature = "bincode"))]
        {
            let key = bytes[0..header.key_len as usize].to_vec();
            let value = bytes[header.key_len as usize..].to_vec();
            Ok(LogEntry { header, key, value })
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

    pub fn tombstone(&mut self) {
        self.header.value_len = 0;
        self.value.clear();
        self.header.timestamp = current_timestamp();
    }

    pub fn is_tombstone(&self) -> bool {
        self.value.is_empty()
    }
}

#[derive(Debug)]
pub enum StorageError {
    Io(std::io::Error),
    Corruption(String),
    Serialization(String),
}

impl Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "IO Error: {e}"),
            Self::Corruption(e) => write!(f, "Corruption: {e}"),
            Self::Serialization(e) => write!(f, "Serialization: {e}"),
        }
    }
}

impl std::error::Error for StorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl StorageError {
    pub fn corruption(e: &str) -> StorageError {
        StorageError::Corruption(e.into())
    }
    pub fn serialization(e: &str) -> StorageError {
        StorageError::Serialization(e.into())
    }
}

impl From<TryFromSliceError> for StorageError {
    fn from(_: TryFromSliceError) -> Self {
        Self::Serialization("slice error".into())
    }
}

#[cfg(feature = "bincode")]
impl From<Box<bincode::ErrorKind>> for StorageError {
    fn from(_: Box<bincode::ErrorKind>) -> Self {
        StorageError::Serialization("serialization error".into())
    }
}

impl From<std::io::Error> for StorageError {
    fn from(err: std::io::Error) -> Self {
        StorageError::Io(err)
    }
}

#[derive(Debug)]
pub struct LogReader {
    path: PathBuf,
    current_file: Option<RefCell<std::fs::File>>,
}

impl LogReader {
    pub fn new(path: &Path) -> Result<Self, StorageError> {
        debug!("LogReader for path {:?}", path);

        Ok(LogReader {
            path: path.to_path_buf(),
            current_file: Some(RefCell::new(Self::open_read_only_file(path)?)),
        })
    }

    fn open_read_only_file(path: &Path) -> Result<std::fs::File, StorageError> {
        Ok(OpenOptions::new().read(true).open(path)?)
    }

    pub fn read_at(&self, offset: Offset, size: Size) -> Result<LogEntry, StorageError> {
        match &self.current_file {
            Some(file) => {
                let mut file = file.borrow_mut();
                file.seek(SeekFrom::Start(offset))?;
                let mut buffer = vec![0u8; size as usize];
                file.read_exact(&mut buffer)?;
                Ok(LogEntry::deserialize(&buffer)?)
            }
            None => Err(StorageError::Io(Error::new(
                ErrorKind::InvalidFilename,
                "Log file not found",
            ))),
        }
    }

    pub fn iter(&self) -> Result<LogReaderIterator, StorageError> {
        let file = Self::open_read_only_file(&self.path)?;
        Ok(LogReaderIterator { file })
    }
}

pub struct LogReaderIterator {
    file: std::fs::File,
}

impl Iterator for LogReaderIterator {
    type Item = LogEntry;

    fn next(&mut self) -> Option<Self::Item> {
        #[cfg(feature = "bincode")]
        {
            None
        }
        #[cfg(not(feature = "bincode"))]
        {
            let mut buffer = [0u8; HEADER_SIZE];
            self.file.read_exact(&mut buffer).ok()?;
            let header = LogEntryHeader::from_bytes(&buffer).ok()?;
            let mut buffer = vec![0u8; (header.key_len + header.value_len) as usize];
            self.file.read_exact(&mut buffer).ok()?;
            let entry = LogEntry::deserialize_with_header(header, &buffer).ok()?;
            Some(entry)
        }
    }
}

pub type Size = u64;

#[derive(Debug)]
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

#[derive(Debug)]
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

pub struct BitcaskOptions {
    size: Size,
}

impl Default for BitcaskOptions {
    fn default() -> Self {
        Self {
            size: ROTATION_FILE_SIZE,
        }
    }
}

impl<T> LogWriter<T>
where
    T: Write + AsRef<[u8]> + Default,
{
    pub fn new(path: &Path) -> Result<Self, StorageError> {
        Self::initialise(path, None)
    }

    pub fn with_options(path: &Path, size: Size) -> Result<Self, StorageError> {
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
    ) -> Result<Self, StorageError> {
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
    }

    fn write_to_buffer(&mut self, bytes: &[u8]) -> Result<u64, StorageError> {
        self.buffer.write_all(&bytes)?;
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

    pub fn rotate(&mut self) -> Result<(), StorageError> {
        if self.rotation_config.is_none() {
            return Err(StorageError::Io(Error::new(
                ErrorKind::InvalidData,
                "No rotation configuration available",
            )));
        }

        self.flush()?;

        let rotation_config = self.rotation_config.as_mut().unwrap();
        let new_file_id = rotation_config.increment_file_id();

        let mut new_file_path = rotation_config.base_dir.clone();
        new_file_path.push(log_file_path(new_file_id));

        self.current_file = new_file_path;
        self.offset = 0;

        Ok(())
    }

    pub fn append(&mut self, entry: &LogEntry) -> Result<Offset, StorageError> {
        Ok(self.append_with_size(entry)?.0)
    }

    pub fn append_with_size(&mut self, entry: &LogEntry) -> Result<(Offset, Size), StorageError> {
        if self.should_rotate(entry) {
            self.rotate()?;
        }
        let bytes = entry.serialize()?;

        // BUG: if the writer is flushed before this will return an offset of 0 as the offset is in the buffer
        let offset = self.write_to_buffer(&bytes)?;
        Ok((offset, bytes.len() as Size))
    }

    fn get_current_file(&self) -> Result<std::fs::File, StorageError> {
        Ok(OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.current_file)?)
    }

    fn write_to_file(&mut self, file: &mut std::fs::File) -> Result<(), StorageError> {
        file.write_all(self.buffer.as_ref())?;
        self.reset_buffer();
        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), StorageError> {
        let mut file = self.get_current_file()?;
        self.write_to_file(&mut file)?;
        Ok(())
    }

    pub fn sync(&mut self) -> Result<(), StorageError> {
        let mut file = self.get_current_file()?;
        self.write_to_file(&mut file)?;
        Ok(file.sync_all()?)
    }
}
