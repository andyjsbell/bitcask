# Bitcask

A Rust implementation of the Bitcask storage model - a log-structured hash table for fast key-value storage.

## Features

- **Append-only log files** - All writes are sequential appends for optimal write performance
- **In-memory index** - Hash table maps keys to log positions for fast lookups
- **CRC validation** - Data integrity checking on all entries
- **Log rotation** - Automatic file rotation based on configurable size limits
- **Single writer, multiple readers** - Lock-free concurrent reads

## Usage

```rust
use bitcask::{LogWriter, LogReader, LogEntry, MemIndex};

// Write entries to log
let mut writer = LogWriter::<Vec<u8>>::new(&path)?;
let mut entry = LogEntry::new(b"key", b"value", timestamp);
entry.calculate_crc();
let (offset, size) = writer.append_with_size(&entry)?;

// Build in-memory index
let mut index = MemIndex::new();
index.insert(b"key".to_vec(), LogPointer::new(0, offset, size, timestamp));

// Read entries using index
let reader = LogReader::new(&path)?;
if let Some(pointer) = index.get(b"key") {
    let entry = reader.read_at(pointer.offset(), pointer.size())?;
}
```

## Architecture

### Core Components

- **LogEntry** - Key-value pair with CRC and timestamp
- **LogWriter** - Buffered sequential writer with rotation support
- **LogReader** - Random and sequential read access
- **MemIndex** - In-memory hash map of keys to log positions
- **LogPointer** - Compact 32-byte structure storing file location

### Storage Format

Each entry is stored as:
```
[CRC:4][key_len:4][value_len:4][timestamp:8][key][value]
```

## Configuration

### Log Rotation

```rust
// Create writer with 10MB file size limit
let writer = LogWriter::<Vec<u8>>::with_options(
    &base_dir,
    10 * 1024 * 1024  // 10MB
)?;
```

## Testing

```bash
cargo test
```

## License

MIT
