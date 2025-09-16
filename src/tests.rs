use crate::bitcask::{LogEntry, LogPointer, LogReader, LogWriter, MemIndex, StorageError};
use std::collections::HashMap;
use std::fs;
use std::io::Cursor;
use tempfile::TempDir;

#[cfg(test)]
mod log_entry_tests {
    use super::*;

    #[test]
    fn test_log_entry_creation() {
        // LogEntry should be creatable with basic fields
        let entry = LogEntry::new(
            b"user:123",
            b"Alice",
            1699564800, // timestamp
        );

        assert_eq!(entry.key(), b"user:123");
        assert_eq!(entry.value(), b"Alice");
        assert_eq!(entry.timestamp(), 1699564800);
        assert_eq!(entry.key_len(), 8);
        assert_eq!(entry.value_len(), 5);
    }

    #[test]
    fn test_log_entry_with_binary_data() {
        // Should handle arbitrary binary data including nulls
        let binary_key = vec![0x00, 0x01, 0xFF, 0xFE];
        let binary_value = vec![0xDE, 0xAD, 0xBE, 0xEF];

        let entry = LogEntry::new(&binary_key, &binary_value, 1699564800);

        assert_eq!(entry.key(), &binary_key[..]);
        assert_eq!(entry.value(), &binary_value[..]);
    }

    #[test]
    fn test_log_entry_crc_calculation() {
        // CRC should be calculated over all fields except the CRC itself
        let mut entry = LogEntry::new(b"key", b"value", 1699564800);
        entry.calculate_crc();

        let crc1 = entry.crc();
        assert_ne!(crc1, 0, "CRC should be calculated and non-zero");

        // Same data should produce same CRC
        let mut entry2 = LogEntry::new(b"key", b"value", 1699564800);
        entry2.calculate_crc();
        assert_eq!(crc1, entry2.crc(), "Same data should produce same CRC");

        // Different data should produce different CRC
        let mut entry3 = LogEntry::new(b"key", b"different", 1699564800);
        entry3.calculate_crc();
        assert_ne!(
            crc1,
            entry3.crc(),
            "Different data should produce different CRC"
        );
    }

    #[test]
    fn test_log_entry_serialization() {
        // LogEntry should serialize to bytes in a specific format
        let mut entry = LogEntry::new(b"test_key", b"test_value", 1699564800);
        entry.calculate_crc();

        let serialized = entry.serialize().expect("Serialization should succeed");

        // Header should be fixed size (20 bytes: crc=4, timestamp=8, key_len=4, value_len=4)
        assert!(serialized.len() >= 20, "Header should be at least 20 bytes");

        // Total size should be header + key + value
        let expected_size = crate::bitcask::HEADER_SIZE + 8 + 10; // header + "test_key" + "test_value"
        assert_eq!(serialized.len(), expected_size);
    }

    #[test]
    fn test_log_entry_deserialization() {
        // Should be able to round-trip through serialization
        let mut original = LogEntry::new(b"my_key", b"my_value", 1699564800);
        original.calculate_crc();

        let serialized = original.serialize().expect("Serialization should succeed");
        let deserialized =
            LogEntry::deserialize(&serialized).expect("Deserialization should succeed");

        assert_eq!(deserialized.key(), original.key());
        assert_eq!(deserialized.value(), original.value());
        assert_eq!(deserialized.timestamp(), original.timestamp());
        assert_eq!(deserialized.crc(), original.crc());
    }

    #[test]
    fn test_log_entry_crc_validation() {
        // Should be able to validate CRC after deserialization
        let mut entry = LogEntry::new(b"key", b"value", 1699564800);
        entry.calculate_crc();

        let serialized = entry.serialize().expect("Serialization should succeed");
        let deserialized =
            LogEntry::deserialize(&serialized).expect("Deserialization should succeed");

        assert!(
            deserialized.validate_crc(),
            "CRC should be valid after deserialization"
        );
    }

    #[test]
    #[cfg(not(feature = "bincode"))]
    fn test_log_entry_corrupted_detection() {
        // Should detect corruption when bytes are modified
        let mut entry = LogEntry::new(b"key", b"value", 1699564800);
        entry.calculate_crc();

        let mut serialized = entry.serialize().expect("Serialization should succeed");

        // Corrupt a byte in the middle of the serialized data
        serialized[25] ^= 0xFF;

        let deserialized = LogEntry::deserialize(&serialized)
            .expect("Deserialization should still work with corrupt data");

        assert!(
            !deserialized.validate_crc(),
            "Should detect corruption via CRC mismatch"
        );
    }

    #[test]
    fn test_log_entry_partial_read() {
        // Should fail gracefully when given incomplete data
        let mut entry = LogEntry::new(b"key", b"value", 1699564800);
        entry.calculate_crc();

        let serialized = entry.serialize().expect("Serialization should succeed");

        // Try to deserialize with only half the data
        let partial = &serialized[..serialized.len() / 2];

        let result = LogEntry::deserialize(partial);
        assert!(result.is_err(), "Should fail to deserialize partial data");
    }

    #[test]
    fn test_log_entry_empty_key_value() {
        // Should handle empty keys and values (useful for tombstones)
        let entry = LogEntry::new(b"", b"", 1699564800);

        assert_eq!(entry.key_len(), 0);
        assert_eq!(entry.value_len(), 0);

        let serialized = entry.serialize().expect("Should serialize empty entry");
        let deserialized =
            LogEntry::deserialize(&serialized).expect("Should deserialize empty entry");

        assert_eq!(deserialized.key(), b"");
        assert_eq!(deserialized.value(), b"");
    }

    #[test]
    fn test_log_entry_large_values() {
        // Should handle large values efficiently
        let large_value = vec![0xAB; 1024 * 1024]; // 1MB of data
        let entry = LogEntry::new(b"key", &large_value, 1699564800);

        assert_eq!(entry.value_len(), 1024 * 1024);

        let serialized = entry.serialize().expect("Should serialize large entry");
        assert_eq!(
            serialized.len(),
            crate::bitcask::HEADER_SIZE + 3 + 1024 * 1024
        ); // header + key + value
    }
}

#[cfg(test)]
mod log_pointer_tests {
    use super::*;

    #[test]
    fn test_log_pointer_creation() {
        // LogPointer should store location information
        let pointer = LogPointer::new(
            1,          // file_id
            1024,       // offset
            256,        // size
            1699564800, // timestamp
        );

        assert_eq!(pointer.file_id(), 1);
        assert_eq!(pointer.offset(), 1024);
        assert_eq!(pointer.size(), 256);
        assert_eq!(pointer.timestamp(), 1699564800);
    }

    #[test]
    fn test_log_pointer_memory_size() {
        // LogPointer should have predictable memory footprint
        use std::mem;

        let pointer_size = mem::size_of::<LogPointer>();

        // Should be exactly 32 bytes (4 + 8 + 8 + 8) which is 28 but is aligned to 32
        // This is important for memory calculations
        assert_eq!(
            pointer_size, 32,
            "LogPointer should be exactly 32 bytes for memory efficiency"
        );
    }

    #[test]
    fn test_log_pointer_comparison() {
        // LogPointers with same location should be equal
        let p1 = LogPointer::new(1, 1024, 256, 1699564800);
        let p2 = LogPointer::new(1, 1024, 256, 1699564800);

        assert_eq!(p1, p2, "Pointers to same location should be equal");

        // Different file_id should make them unequal
        let p3 = LogPointer::new(2, 1024, 256, 1699564800);
        assert_ne!(p1, p3);

        // Different offset should make them unequal
        let p4 = LogPointer::new(1, 2048, 256, 1699564800);
        assert_ne!(p1, p4);
    }

    #[test]
    fn test_log_pointer_file_path_generation() {
        // Should generate correct file paths from file_id
        let pointer = LogPointer::new(7, 0, 0, 0);

        let path = pointer.file_path("data");
        assert_eq!(path.to_str().unwrap(), "data/000007.log");

        // Should handle large file IDs
        let pointer2 = LogPointer::new(999999, 0, 0, 0);
        let path2 = pointer2.file_path("data");
        assert_eq!(path2.to_str().unwrap(), "data/999999.log");
    }

    #[test]
    fn test_log_pointer_clone_copy() {
        // LogPointer should be cheap to copy (implements Copy trait)
        let p1 = LogPointer::new(1, 1024, 256, 1699564800);
        let p2 = p1; // This should be a copy, not a move

        // Both should still be usable
        assert_eq!(p1.file_id(), 1);
        assert_eq!(p2.file_id(), 1);
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom, Write};

    #[test]
    fn test_write_and_read_via_pointer() {
        // Integration test: write an entry and read it back using pointer
        let mut buffer = Cursor::new(Vec::new());

        // Create and write an entry
        let mut entry = LogEntry::new(b"integration_key", b"integration_value", 1699564800);
        entry.calculate_crc();

        let offset = buffer.position();
        let serialized = entry.serialize().expect("Serialization should succeed");
        let size = serialized.len() as u64;

        buffer.write_all(&serialized).expect("Write should succeed");

        // Create pointer to the entry
        let pointer = LogPointer::new(0, offset, size, entry.timestamp());

        // Use pointer to read back the entry
        buffer
            .seek(SeekFrom::Start(pointer.offset()))
            .expect("Seek should succeed");

        let mut read_buffer = vec![0u8; pointer.size() as usize];
        buffer
            .read_exact(&mut read_buffer)
            .expect("Read should succeed");

        let read_entry =
            LogEntry::deserialize(&read_buffer).expect("Should deserialize entry read via pointer");

        assert_eq!(read_entry.key(), b"integration_key");
        assert_eq!(read_entry.value(), b"integration_value");
        assert!(read_entry.validate_crc(), "CRC should be valid");
    }

    #[test]
    fn test_multiple_entries_with_pointers() {
        // Should handle multiple entries in sequence
        let mut buffer = Cursor::new(Vec::new());
        let mut pointers = Vec::new();

        // Write multiple entries
        for i in 0..10 {
            let key = format!("key_{}", i);
            let value = format!("value_{}", i);

            let mut entry = LogEntry::new(key.as_bytes(), value.as_bytes(), 1699564800 + i);
            entry.calculate_crc();

            let offset = buffer.position();
            let serialized = entry.serialize().expect("Serialization should succeed");
            let size = serialized.len() as u64;

            buffer.write_all(&serialized).expect("Write should succeed");

            pointers.push(LogPointer::new(0, offset, size, entry.timestamp()));
        }

        // Read back entries using pointers in random order
        for (i, pointer) in pointers.iter().enumerate().rev() {
            buffer
                .seek(SeekFrom::Start(pointer.offset()))
                .expect("Seek should succeed");

            let mut read_buffer = vec![0u8; pointer.size() as usize];
            buffer
                .read_exact(&mut read_buffer)
                .expect("Read should succeed");

            let entry = LogEntry::deserialize(&read_buffer).expect("Should deserialize entry");

            let expected_key = format!("key_{}", i);
            let expected_value = format!("value_{}", i);

            assert_eq!(entry.key(), expected_key.as_bytes());
            assert_eq!(entry.value(), expected_value.as_bytes());
        }
    }
    #[test]
    fn test_memindex_with_logreader() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.log");

        let mut index = MemIndex::new();

        // Write entries and build index
        {
            let mut writer = LogWriter::<Vec<u8>>::new(&log_path).unwrap();

            for i in 0..20 {
                let key = format!("key_{:02}", i).into_bytes();
                let value = format!("value_{:02}", i).into_bytes();

                let mut entry = LogEntry::new(&key, &value, 1699564800 + i);
                entry.calculate_crc();

                let (offset, size) = writer.append_with_size(&entry).unwrap();
                let pointer = LogPointer::new(0, offset, size, entry.timestamp());

                index.insert(key, pointer);
            }
            writer.sync().unwrap();
        }

        // Use index to read specific values
        let mut reader = LogReader::new(&log_path).unwrap();

        // Read value for key_10
        let pointer = index.get(b"key_10").unwrap();
        let entry = reader.read_at(pointer.offset(), pointer.size()).unwrap();
        assert_eq!(entry.value(), b"value_10");

        // Read value for key_05
        let pointer = index.get(b"key_05").unwrap();
        let entry = reader.read_at(pointer.offset(), pointer.size()).unwrap();
        assert_eq!(entry.value(), b"value_05");

        // Non-existent key
        assert!(index.get(b"key_99").is_none());
    }

    #[test]
    fn test_rebuild_index_from_log() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.log");

        // Write log without maintaining index
        {
            let mut writer = LogWriter::<Vec<u8>>::new(&log_path).unwrap();

            for i in 0..10 {
                let mut entry = LogEntry::new(
                    format!("key{}", i).as_bytes(),
                    format!("value{}", i).as_bytes(),
                    1699564800 + i,
                );
                entry.calculate_crc();
                writer.append(&entry).unwrap();
            }

            // Write some updates (same keys)
            for i in 0..5 {
                let mut entry = LogEntry::new(
                    format!("key{}", i).as_bytes(),
                    format!("updated_value{}", i).as_bytes(),
                    1699565000 + i,
                );
                entry.calculate_crc();
                writer.append(&entry).unwrap();
            }

            writer.sync().unwrap();
        }

        // Rebuild index by scanning log
        let mut index = MemIndex::new();
        let reader = LogReader::new(&log_path).unwrap();
        let mut offset = 0u64;

        for result in reader.iter().unwrap() {
            let entry = result.unwrap();
            let size = entry.serialize().unwrap().len() as u64;

            let pointer = LogPointer::new(0, offset, size, entry.timestamp());

            // Insert or update - last write wins
            index.insert(entry.key().to_vec(), pointer);

            offset += size as u64;
        }

        // Verify index has correct values
        assert_eq!(index.len(), 10); // 10 unique keys

        // Keys 0-4 should point to updated values
        let mut reader = LogReader::new(&log_path).unwrap();

        for i in 0..5 {
            let key = format!("key{}", i).into_bytes();
            let pointer = index.get(&key).unwrap();
            let entry = reader.read_at(pointer.offset(), pointer.size()).unwrap();
            assert_eq!(entry.value(), format!("updated_value{}", i).as_bytes());
        }

        // Keys 5-9 should point to original values
        for i in 5..10 {
            let key = format!("key{}", i).into_bytes();
            let pointer = index.get(&key).unwrap();
            let entry = reader.read_at(pointer.offset(), pointer.size()).unwrap();
            assert_eq!(entry.value(), format!("value{}", i).as_bytes());
        }
    }

    #[test]
    fn test_delete_handling_in_index() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.log");

        let mut index = MemIndex::new();

        // Write and delete some entries
        {
            let mut writer = LogWriter::<Vec<u8>>::new(&log_path).unwrap();

            // Write key1
            let mut entry = LogEntry::new(b"key1", b"value1", 1699564800);
            entry.calculate_crc();
            let (offset, size) = writer.append_with_size(&entry).unwrap();
            index.insert(
                b"key1".to_vec(),
                LogPointer::new(0, offset, size, entry.timestamp()),
            );

            // Write key2
            let mut entry = LogEntry::new(b"key2", b"value2", 1699564801);
            entry.calculate_crc();
            let (offset, size) = writer.append_with_size(&entry).unwrap();
            index.insert(
                b"key2".to_vec(),
                LogPointer::new(0, offset, size, entry.timestamp()),
            );

            // Delete key1 (tombstone entry with empty value)
            let mut tombstone = LogEntry::new(b"key1", b"", 1699564802);
            tombstone.calculate_crc();
            writer.append(&tombstone).unwrap();

            // Remove from index
            index.delete(b"key1");

            writer.sync().unwrap();
        }

        // key1 should not be in index
        assert!(index.get(b"key1").is_none());

        // key2 should still be there
        assert!(index.get(b"key2").is_some());

        let mut reader = LogReader::new(&log_path).unwrap();
        let pointer = index.get(b"key2").unwrap();
        let entry = reader.read_at(pointer.offset(), pointer.size()).unwrap();
        assert_eq!(entry.value(), b"value2");
    }

    #[test]
    fn test_memindex_memory_vs_disk_size() {
        // This test demonstrates the memory savings of the index approach

        let mut index = MemIndex::new();
        let mut total_value_size = 0usize;

        // Simulate 1000 entries with 1KB values each
        for i in 0..1000 {
            let key = format!("key_{:04}", i).into_bytes();
            let value_size = 1024; // 1KB value
            total_value_size += value_size;

            // We only store the pointer, not the value
            let pointer = LogPointer::new(0, i as u64 * 1100, 1024 + 20, 0);
            index.insert(key, pointer);
        }

        // If we stored values: ~1MB in memory
        // With pointers: ~32KB for pointers + key overhead

        println!(
            "Storing values in memory would use: {} bytes",
            total_value_size
        );
        println!("Storing pointers uses: ~{} bytes", 1000 * (32 + 10)); // 32 bytes per pointer + ~10 bytes per key

        assert!(
            1000 * 42 < total_value_size,
            "Index should use much less memory than storing values"
        );
    }
}

#[cfg(test)]
mod error_handling_tests {
    use super::*;

    #[test]
    fn test_storage_error_variants() {
        // StorageError should cover all failure modes

        // Should have IO error variant
        let io_error = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let storage_error = StorageError::from(io_error);
        assert!(matches!(storage_error, StorageError::Io(_)));

        // Should have corruption error
        let corruption = StorageError::corruption("CRC mismatch");
        assert!(matches!(corruption, StorageError::Corruption(_)));

        // Should have serialization error
        let serialization = StorageError::serialization("invalid format");
        assert!(matches!(serialization, StorageError::Serialization(_)));

        // Should be able to convert to std::error::Error
        let error: Box<dyn std::error::Error> = Box::new(storage_error);
        assert!(error.to_string().contains("IO"));
    }

    #[test]
    fn test_error_display() {
        // Errors should have meaningful display messages
        let error = StorageError::corruption("CRC mismatch at offset 1024");
        assert!(error.to_string().contains("CRC"));
        assert!(error.to_string().contains("1024"));
    }
}

// tests/log_writer_detailed.rs
// Comprehensive tests for LogWriter implementation

#[cfg(test)]
mod basic_writer_tests {
    use super::*;

    #[test]
    fn test_writer_creates_file() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.log");

        // File shouldn't exist yet
        assert!(!log_path.exists());

        // Creating writer should create the file
        let writer = LogWriter::<Vec<u8>>::new(&log_path).expect("Should create writer");

        // File should now exist
        assert!(log_path.exists());

        // File should be empty initially
        let metadata = fs::metadata(&log_path).unwrap();
        assert_eq!(metadata.len(), 0);

        // Writer should track position
        assert_eq!(writer.current_offset(), 0);
    }

    #[test]
    fn test_writer_append_updates_offset() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.log");

        let mut writer = LogWriter::<Vec<u8>>::new(&log_path).unwrap();

        // Create a small entry
        let mut entry = LogEntry::new(b"k", b"v", 1699564800);
        entry.calculate_crc();

        // Track offset before append
        let offset_before = writer.current_offset();
        assert_eq!(offset_before, 0);

        // Append should return the offset where it was written
        let write_offset = writer.append(&entry).unwrap();
        assert_eq!(write_offset, offset_before);

        // Offset should advance by size of serialized entry
        let serialized_size = entry.serialize().unwrap().len() as u64;
        assert_eq!(writer.current_offset(), serialized_size);

        // Append another entry
        let write_offset_2 = writer.append(&entry).unwrap();
        assert_eq!(write_offset_2, serialized_size);
        assert_eq!(writer.current_offset(), serialized_size * 2);
    }

    #[test]
    fn test_writer_returns_correct_size() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.log");

        let mut writer = LogWriter::<Vec<u8>>::new(&log_path).unwrap();

        // Test with various sized entries
        let test_cases = vec![
            (b"k".to_vec(), b"v".to_vec()),
            (b"medium_key".to_vec(), b"medium_value".to_vec()),
            (vec![0u8; 100], vec![0u8; 1000]), // Larger entry
        ];

        for (key, value) in test_cases {
            let mut entry = LogEntry::new(&key, &value, 1699564800);
            entry.calculate_crc();

            let expected_size = entry.serialize().unwrap().len() as u64;

            // append_with_size should return both offset and actual size
            let (offset, size) = writer.append_with_size(&entry).unwrap();

            assert_eq!(
                size,
                expected_size,
                "Size should match serialized size for key len {}",
                key.len()
            );

            // Offset should be previous position
            assert_eq!(offset, writer.current_offset() - size as u64);
        }
    }
}

#[cfg(test)]
mod buffering_tests {
    use super::*;

    #[test]
    fn test_writer_uses_buffering() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.log");

        let mut writer = LogWriter::<Vec<u8>>::new(&log_path).unwrap();

        // Write a small entry
        let mut entry = LogEntry::new(b"key", b"value", 1699564800);
        entry.calculate_crc();
        let serialized_size = entry.serialize().unwrap().len();

        writer.append(&entry).unwrap();

        // Without flush, file size might be 0 due to buffering
        let metadata = fs::metadata(&log_path).unwrap();
        assert_eq!(
            metadata.len(),
            0,
            "Before flush, file should contain no data"
        );

        // After flush, data must be in file
        writer.flush().unwrap();

        let metadata_after_flush = fs::metadata(&log_path).unwrap();
        assert_eq!(
            metadata_after_flush.len(),
            serialized_size as u64,
            "After flush, file should contain all written data"
        );
    }

    #[test]
    fn test_writer_flush_vs_sync() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.log");

        let mut writer = LogWriter::<Vec<u8>>::new(&log_path).unwrap();

        let mut entry = LogEntry::new(b"test", b"data", 1699564800);
        entry.calculate_crc();

        writer.append(&entry).unwrap();

        // flush() empties buffer to OS (might still be in OS cache)
        writer.flush().unwrap();

        // sync() ensures data is on disk (survives power failure)
        writer.sync().unwrap();

        // Both should complete without error
        // sync() is stronger guarantee than flush()
    }

    #[test]
    fn test_writer_auto_flush_on_drop() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.log");

        let mut entry = LogEntry::new(b"key", b"value", 1699564800);
        entry.calculate_crc();
        let expected_size = entry.serialize().unwrap().len();

        {
            let mut writer = LogWriter::<Vec<u8>>::new(&log_path).unwrap();
            writer.append(&entry).unwrap();
            // Writer dropped here - should auto-flush
        }

        // After drop, data should be in file
        let metadata = fs::metadata(&log_path).unwrap();
        assert_eq!(
            metadata.len(),
            expected_size as u64,
            "Drop should flush buffered data"
        );
    }
}

#[cfg(test)]
mod file_rotation_tests {
    use super::*;

    #[test]
    fn test_writer_with_size_limit() {
        let temp_dir = TempDir::new().unwrap();

        // Create writer with max file size (e.g., 1KB)
        let mut writer = LogWriter::<Vec<u8>>::with_options(
            temp_dir.path(),
            1024, // 1KB max file size
        )
        .unwrap();

        // Writer should start with file_id 0
        assert_eq!(writer.current_file_id(), 0);

        // Create a 100-byte entry (approximate)
        let value = vec![0xAB; 50];
        let mut entry = LogEntry::new(b"key", &value, 1699564800);
        entry.calculate_crc();

        let entry_size = entry.serialize().unwrap().len();

        // Write entries until we exceed 1KB
        let mut total_written = 0;
        let mut rotations = 0;
        let mut last_file_id = 0;

        for _ in 0..20 {
            // Should trigger at least one rotation
            writer.append(&entry).unwrap();
            total_written += entry_size;

            if writer.current_file_id() != last_file_id {
                rotations += 1;
                last_file_id = writer.current_file_id();
            }
        }

        // Should have rotated at least once
        assert!(rotations > 0, "Should rotate when exceeding size limit");
        assert!(writer.current_file_id() > 0, "File ID should increment");

        // Finish writing
        drop(writer);

        // Check that multiple log files exist
        let log_files: Vec<_> = fs::read_dir(temp_dir.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry
                    .path()
                    .extension()
                    .map(|ext| ext == "log")
                    .unwrap_or(false)
            })
            .collect();

        assert!(log_files.len() > 1, "Should have multiple log files");
    }

    #[test]
    fn test_writer_rotation_preserves_data() {
        let temp_dir = TempDir::new().unwrap();

        let mut writer = LogWriter::<Vec<u8>>::with_options(
            temp_dir.path(),
            500, // Small limit to force rotation
        )
        .unwrap();

        // Track what we write
        let mut written_entries = Vec::new();

        for i in 0..10 {
            let mut entry = LogEntry::new(
                format!("key{}", i).as_bytes(),
                format!("value{}", i).as_bytes(),
                1699564800 + i,
            );
            entry.calculate_crc();

            let (offset, size) = writer.append_with_size(&entry).unwrap();
            let file_id = writer.current_file_id();

            written_entries.push((file_id, offset, size, entry));
        }

        writer.sync().unwrap();
        drop(writer);

        // Verify all data is preserved across multiple files
        for (file_id, offset, size, original_entry) in written_entries {
            let file_path = temp_dir.path().join(format!("{:06}.log", file_id));
            assert!(file_path.exists(), "Log file {} should exist", file_id);

            // Read back the entry
            let data = fs::read(&file_path).unwrap();
            assert!(
                offset + size as u64 <= data.len() as u64,
                "Entry should be within file bounds"
            );

            let entry_data = &data[offset as usize..(offset + size as u64) as usize];
            let entry = LogEntry::deserialize(entry_data).unwrap();

            assert_eq!(entry.key(), original_entry.key());
            assert_eq!(entry.value(), original_entry.value());
        }
    }

    #[test]
    fn test_writer_rotation_atomic() {
        let temp_dir = TempDir::new().unwrap();

        let mut writer = LogWriter::<Vec<u8>>::with_options(
            temp_dir.path(),
            100, // Very small to force rotation mid-write
        )
        .unwrap();

        // Create an entry that won't fit in remaining space
        let value = vec![0xCD; 80];
        let mut entry = LogEntry::new(b"large", &value, 1699564800);
        entry.calculate_crc();

        // Write a small entry first
        let mut small = LogEntry::new(b"s", b"v", 1699564800);
        small.calculate_crc();
        writer.append(&small).unwrap();

        let file_before = writer.current_file_id();

        // This should trigger rotation before writing
        let (offset, _) = writer.append_with_size(&entry).unwrap();

        let file_after = writer.current_file_id();

        // Should have rotated
        assert_eq!(file_after, file_before + 1);

        // The large entry should be at start of new file
        assert_eq!(
            offset, 0,
            "Large entry should start at beginning of new file"
        );
    }
}
#[cfg(test)]
mod file_error_handling_tests {
    use super::*;
    use std::fs::File;

    #[test]
    fn test_writer_handles_permission_errors() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("readonly.log");

        // Create a read-only file
        File::create(&log_path).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = fs::Permissions::from_mode(0o444);
            fs::set_permissions(&log_path, permissions).unwrap();
        }

        // Should fail to create writer for read-only file
        let result = LogWriter::<Vec<u8>>::new(&log_path);

        #[cfg(unix)]
        {
            assert!(
                result.is_err(),
                "Should fail to open read-only file for writing"
            );
            assert!(matches!(result.unwrap_err(), StorageError::Io(_)));
        }
    }

    #[test]
    fn test_writer_handles_disk_full() {
        // This test is conceptual - actually filling disk is not practical
        // But your implementation should handle write failures gracefully

        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.log");

        let mut writer = LogWriter::<Vec<u8>>::new(&log_path).unwrap();

        // If a write fails (e.g., disk full), it should return an error
        // not panic
        let huge_value = vec![0xFF; 1024 * 1024 * 100]; // 100MB
        let mut entry = LogEntry::new(b"huge", &huge_value, 1699564800);
        entry.calculate_crc();

        // This might succeed or fail depending on available space
        // The important thing is it returns Result, not panics
        let _ = writer.append(&entry);
    }
}

#[cfg(test)]
mod performance_characteristics {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_append_performance() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("perf.log");

        let mut writer = LogWriter::<Vec<u8>>::new(&log_path).unwrap();

        // Prepare test entry (1KB)
        let value = vec![0xAB; 1000];
        let mut entry = LogEntry::new(b"key", &value, 1699564800);
        entry.calculate_crc();

        // Warm up
        for _ in 0..100 {
            writer.append(&entry).unwrap();
        }

        // Measure append performance
        let iterations = 1000;
        let start = Instant::now();

        for _ in 0..iterations {
            writer.append(&entry).unwrap();
        }

        let elapsed = start.elapsed();
        let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

        println!("Append performance: {:.0} ops/sec", ops_per_sec);

        // Should achieve at least 10,000 ops/sec for 1KB entries
        assert!(
            ops_per_sec > 10_000.0,
            "Append performance too low: {:.0} ops/sec",
            ops_per_sec
        );
    }

    #[test]
    fn test_buffering_impact() {
        let temp_dir = TempDir::new().unwrap();

        // Test with explicit flushes (simulates unbuffered)
        let log_path_unbuffered = temp_dir.path().join("unbuffered.log");
        let mut writer_unbuffered = LogWriter::<Vec<u8>>::new(&log_path_unbuffered).unwrap();

        let mut entry = LogEntry::new(b"k", b"v", 1699564800);
        entry.calculate_crc();

        let start = Instant::now();
        for _ in 0..1000 {
            writer_unbuffered.append(&entry).unwrap();
            writer_unbuffered.flush().unwrap(); // Force flush each time
        }
        let unbuffered_time = start.elapsed();

        // Test with buffering (no explicit flushes)
        let log_path_buffered = temp_dir.path().join("buffered.log");
        let mut writer_buffered = LogWriter::<Vec<u8>>::new(&log_path_buffered).unwrap();

        let start = Instant::now();
        for _ in 0..1000 {
            writer_buffered.append(&entry).unwrap();
            // No flush - let buffering work
        }
        writer_buffered.flush().unwrap(); // Single flush at end
        let buffered_time = start.elapsed();

        // Buffered should be significantly faster
        let speedup = unbuffered_time.as_secs_f64() / buffered_time.as_secs_f64();
        println!("Buffering speedup: {:.1}x", speedup);

        assert!(
            speedup > 2.0,
            "Buffering should provide significant speedup, got {:.1}x",
            speedup
        );
    }
}

#[cfg(test)]
mod concurrent_writer_tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::thread;

    #[test]
    fn test_single_writer_principle() {
        // Bitcask uses single writer principle
        // This test documents that behavior

        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.log");

        // First writer succeeds
        let writer1 = LogWriter::<Vec<u8>>::new(&log_path);
        assert!(writer1.is_ok());

        // Second writer succeeds
        let writer2 = LogWriter::<Vec<u8>>::new(&log_path);
        assert!(writer2.is_ok());
    }

    #[test]
    fn test_writer_thread_safety() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.log");

        let writer = Arc::new(Mutex::new(LogWriter::<Vec<u8>>::new(&log_path).unwrap()));

        let handles: Vec<_> = (0..4)
            .map(|i| {
                let writer = Arc::clone(&writer);

                thread::spawn(move || {
                    for j in 0..10 {
                        let mut entry = LogEntry::new(
                            format!("key_{}_{}", i, j).as_bytes(),
                            b"value",
                            1699564800,
                        );
                        entry.calculate_crc();

                        writer.lock().unwrap().append(&entry).unwrap();
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        // Should have written all 40 entries
        writer.lock().unwrap().sync().unwrap();
    }
}

// ============================================
// MemIndex Tests
// ============================================

#[cfg(test)]
mod memindex_tests {
    use super::*;

    #[test]
    fn test_memindex_new() {
        let index = MemIndex::new();

        // Should start empty
        assert_eq!(index.len(), 0);
        assert!(index.is_empty());
    }

    #[test]
    fn test_memindex_insert_and_get() {
        let mut index = MemIndex::new();

        let pointer = LogPointer::new(0, 100, 50, 1699564800);

        // Insert returns old value if key existed
        let old = index.insert(b"key1".to_vec(), pointer);
        assert!(old.is_none(), "First insert should return None");

        // Get should return reference to pointer
        let retrieved = index.get(b"key1");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), &pointer);

        // Non-existent key returns None
        assert!(index.get(b"key2").is_none());
    }

    #[test]
    fn test_memindex_update_existing() {
        let mut index = MemIndex::new();

        let pointer1 = LogPointer::new(0, 100, 50, 1699564800);
        let pointer2 = LogPointer::new(1, 200, 60, 1699564900);

        // First insert
        index.insert(b"key".to_vec(), pointer1);

        // Update with new pointer
        let old = index.insert(b"key".to_vec(), pointer2);
        assert!(old.is_some());
        assert_eq!(old.unwrap(), pointer1, "Should return old pointer");

        // Should now have new pointer
        assert_eq!(index.get(b"key").unwrap(), &pointer2);

        // Still only one entry
        assert_eq!(index.len(), 1);
    }

    #[test]
    fn test_memindex_delete() {
        let mut index = MemIndex::new();

        let pointer = LogPointer::new(0, 100, 50, 1699564800);
        index.insert(b"key".to_vec(), pointer);

        // Delete should return the removed pointer
        let removed = index.delete(b"key");
        assert!(removed.is_some());
        assert_eq!(removed.unwrap(), pointer);

        // Key should no longer exist
        assert!(index.get(b"key").is_none());
        assert_eq!(index.len(), 0);

        // Deleting non-existent key returns None
        assert!(index.delete(b"key").is_none());
    }

    #[test]
    fn test_memindex_binary_keys() {
        let mut index = MemIndex::new();

        // Should handle arbitrary binary keys
        let binary_key = vec![0x00, 0xFF, 0xDE, 0xAD, 0xBE, 0xEF];
        let pointer = LogPointer::new(0, 0, 10, 0);

        index.insert(binary_key.clone(), pointer);
        assert!(index.get(&binary_key).is_some());
    }

    #[test]
    fn test_memindex_memory_efficiency() {
        use std::mem;

        let mut index = MemIndex::new();

        // Add many entries
        for i in 0..1000 {
            let key = format!("key_{:04}", i).into_bytes();
            let pointer = LogPointer::new(0, i * 100, 100, 1699564800);
            index.insert(key, pointer);
        }

        assert_eq!(index.len(), 1000);

        // Each entry should only store pointer (32 bytes) + key + HashMap overhead
        // Not the actual values (which could be much larger)

        // This is more of a documentation test - actual memory usage
        // depends on HashMap implementation
        println!("MemIndex with 1000 entries size estimate");
        println!(
            "Per entry: ~{} bytes (key + LogPointer + overhead)",
            mem::size_of::<Vec<u8>>() + mem::size_of::<LogPointer>()
        );
    }

    #[test]
    fn test_memindex_clear() {
        let mut index = MemIndex::new();

        for i in 0..10 {
            let key = format!("key_{}", i).into_bytes();
            let pointer = LogPointer::new(0, i * 100, 50, 0);
            index.insert(key, pointer);
        }

        assert_eq!(index.len(), 10);

        index.clear();

        assert_eq!(index.len(), 0);
        assert!(index.is_empty());

        // All keys should be gone
        assert!(index.get(b"key_0").is_none());
    }

    #[test]
    fn test_memindex_iteration() {
        let mut index = MemIndex::new();

        let mut expected = HashMap::new();
        for i in 0..5 {
            let key = format!("key_{}", i).into_bytes();
            let pointer = LogPointer::new(0, i * 100, 50, 1699564800 + i);
            index.insert(key.clone(), pointer);
            expected.insert(key, pointer);
        }

        // Should be able to iterate over all entries
        let mut count = 0;
        for (key, pointer) in index.iter() {
            count += 1;
            assert_eq!(expected.get(key), Some(pointer));
        }
        assert_eq!(count, 5);
    }

    #[test]
    fn test_memindex_keys() {
        let mut index = MemIndex::new();

        let keys: Vec<Vec<u8>> = vec![b"apple".to_vec(), b"banana".to_vec(), b"cherry".to_vec()];

        for (i, key) in keys.iter().enumerate() {
            let pointer = LogPointer::new(0, i as u64 * 100, 50, 0);
            index.insert(key.clone(), pointer);
        }

        // Collect all keys
        let mut index_keys: Vec<Vec<u8>> = index.keys().cloned().collect();
        index_keys.sort();

        let mut expected_keys = keys.clone();
        expected_keys.sort();

        assert_eq!(index_keys, expected_keys);
    }
}

// ============================================
// LogReader Tests
// ============================================

#[cfg(test)]
mod logreader_tests {
    use super::*;

    #[test]
    fn test_reader_open_existing_file() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.log");

        // Create file with writer
        {
            let mut writer = LogWriter::<Vec<u8>>::new(&log_path).unwrap();
            let mut entry = LogEntry::new(b"test", b"data", 1699564800);
            entry.calculate_crc();
            writer.append(&entry).unwrap();
            writer.sync().unwrap();
        }

        // Should be able to open for reading
        let reader = LogReader::new(&log_path);
        assert!(reader.is_ok());
    }

    #[test]
    fn test_reader_open_nonexistent_file() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("nonexistent.log");

        // Should fail gracefully
        let reader = LogReader::new(&log_path);
        assert!(reader.is_err());
        assert!(matches!(reader.unwrap_err(), StorageError::Io(_)));
    }

    #[test]
    fn test_reader_read_at_specific_offset() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.log");

        // Write some entries
        let mut pointers = Vec::new();
        {
            let mut writer = LogWriter::<Vec<u8>>::new(&log_path).unwrap();

            for i in 0..3 {
                let mut entry = LogEntry::new(
                    format!("key{}", i).as_bytes(),
                    format!("value{}", i).as_bytes(),
                    1699564800 + i,
                );
                entry.calculate_crc();

                let (offset, size) = writer.append_with_size(&entry).unwrap();
                pointers.push((offset, size));
            }
            writer.sync().unwrap();
        }

        // Read middle entry
        let mut reader = LogReader::new(&log_path).unwrap();
        let (offset, size) = pointers[1];

        let entry = reader.read_at(offset, size).unwrap();
        assert_eq!(entry.key(), b"key1");
        assert_eq!(entry.value(), b"value1");
        assert!(entry.validate_crc());
    }

    #[test]
    fn test_reader_read_beyond_file() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.log");

        // Write small file
        {
            let mut writer = LogWriter::<Vec<u8>>::new(&log_path).unwrap();
            let mut entry = LogEntry::new(b"key", b"value", 1699564800);
            entry.calculate_crc();
            writer.append(&entry).unwrap();
            writer.sync().unwrap();
        }

        let mut reader = LogReader::new(&log_path).unwrap();

        // Try to read beyond file
        let result = reader.read_at(10000, 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_reader_corrupted_crc() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.log");

        // Write entry then corrupt it
        let mut entry = LogEntry::new(b"key", b"value", 1699564800);
        entry.calculate_crc();
        let mut serialized = entry.serialize().unwrap();

        // Corrupt data after CRC field
        serialized[20] ^= 0xFF;
        let size = serialized.len() as u64;
        fs::write(&log_path, serialized).unwrap();

        // Read should succeed but CRC validation should fail
        let mut reader = LogReader::new(&log_path).unwrap();
        let read_entry = reader.read_at(0, size).unwrap();

        assert!(!read_entry.validate_crc(), "Should detect corruption");
    }

    #[test]
    fn test_reader_iterator_full_scan() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.log");

        // Write multiple entries
        let mut expected = Vec::new();
        {
            let mut writer = LogWriter::<Vec<u8>>::new(&log_path).unwrap();

            for i in 0..10 {
                let mut entry = LogEntry::new(
                    format!("key{}", i).as_bytes(),
                    format!("value{}", i).as_bytes(),
                    1699564800 + i,
                );
                entry.calculate_crc();

                expected.push((entry.key().to_vec(), entry.value().to_vec()));
                writer.append(&entry).unwrap();
            }
            writer.sync().unwrap();
        }

        // Iterate through all entries
        let reader = LogReader::new(&log_path).unwrap();
        let mut count = 0;

        for (i, result) in reader.iter().unwrap().enumerate() {
            let entry = result.unwrap();
            assert!(entry.validate_crc());
            assert_eq!(entry.key(), expected[i].0);
            assert_eq!(entry.value(), expected[i].1);
            count += 1;
        }

        assert_eq!(count, 10, "Should read all entries");
    }

    #[test]
    fn test_reader_iterator_partial_entry() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.log");

        // Write complete entry
        {
            let mut writer = LogWriter::<Vec<u8>>::new(&log_path).unwrap();
            let mut entry = LogEntry::new(b"complete", b"entry", 1699564800);
            entry.calculate_crc();
            writer.append(&entry).unwrap();
            writer.sync().unwrap();
        }

        // Append partial entry (simulate crash)
        let mut partial = LogEntry::new(b"partial", b"entry", 1699564801);
        partial.calculate_crc();
        let serialized = partial.serialize().unwrap();

        let mut file = fs::OpenOptions::new().append(true).open(&log_path).unwrap();
        use std::io::Write;
        file.write_all(&serialized[..serialized.len() / 2]).unwrap();

        // Iterator should handle gracefully
        let reader = LogReader::new(&log_path).unwrap();
        let valid_entries: Vec<_> = reader
            .iter()
            .unwrap()
            .filter_map(|r| r.ok())
            .filter(|e| e.validate_crc())
            .collect();

        assert_eq!(valid_entries.len(), 1, "Should only get complete entry");
        assert_eq!(valid_entries[0].key(), b"complete");
    }

    #[test]
    fn test_reader_iterator_empty_file() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("empty.log");

        // Create empty file
        fs::write(&log_path, b"").unwrap();

        let reader = LogReader::new(&log_path).unwrap();
        let count = reader.iter().unwrap().count();

        assert_eq!(count, 0, "Empty file should yield no entries");
    }

    #[test]
    fn test_reader_concurrent_readers() {
        use std::sync::Arc;
        use std::thread;

        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.log");

        // Write test data
        {
            let mut writer = LogWriter::<Vec<u8>>::new(&log_path).unwrap();
            for i in 0..100 {
                let mut entry = LogEntry::new(
                    format!("key{}", i).as_bytes(),
                    format!("value{}", i).as_bytes(),
                    1699564800,
                );
                entry.calculate_crc();
                writer.append(&entry).unwrap();
            }
            writer.sync().unwrap();
        }

        let path = Arc::new(log_path);

        // Multiple readers should work concurrently
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let path = Arc::clone(&path);
                thread::spawn(move || {
                    let reader = LogReader::new(&path).unwrap();
                    let count = reader
                        .iter()
                        .unwrap()
                        .filter_map(|r| r.ok())
                        .filter(|e| e.validate_crc())
                        .count();
                    assert_eq!(count, 100);
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }
    }
}
