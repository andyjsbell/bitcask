use crate::bitcask::{
    Bitcask, BitcaskOptions, LogEntry, LogPointer, LogReader, LogWriter, MemIndex, StorageError,
};
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
    use std::path::PathBuf;

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

        let path = pointer.file_path(&PathBuf::from("data"));
        assert_eq!(path.to_str().unwrap(), "data/000007.log");

        // Should handle large file IDs
        let pointer2 = LogPointer::new(999999, 0, 0, 0);
        let path2 = pointer2.file_path(&PathBuf::from("data"));
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
        let reader = LogReader::new(&log_path).unwrap();

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

        for entry in reader.iter().unwrap() {
            let size = entry.serialize().unwrap().len() as u64;

            let pointer = LogPointer::new(0, offset, size, entry.timestamp());

            // Insert or update - last write wins
            index.insert(entry.key().to_vec(), pointer);

            offset += size as u64;
        }

        // Verify index has correct values
        assert_eq!(index.len(), 10); // 10 unique keys

        // Keys 0-4 should point to updated values
        let reader = LogReader::new(&log_path).unwrap();

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

        let reader = LogReader::new(&log_path).unwrap();
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

        let mut rotations = 0;
        let mut last_file_id = 0;

        for _ in 0..20 {
            // Should trigger at least one rotation
            writer.append(&entry).unwrap();

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
        let reader = LogReader::new(&log_path).unwrap();
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

        let reader = LogReader::new(&log_path).unwrap();

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
        let reader = LogReader::new(&log_path).unwrap();
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

        for (i, entry) in reader.iter().unwrap().enumerate() {
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
                    let count = reader.iter().unwrap().filter(|e| e.validate_crc()).count();
                    assert_eq!(count, 100);
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }
    }
}

mod tombstone_tests {
    use super::*;

    #[test]
    fn test_logentry_tombstone_creation() {
        // Test that we can create a tombstone entry

        // Option 1: Empty value as tombstone
        let tombstone = LogEntry::new(b"deleted_key", b"", 1699564800);
        assert_eq!(tombstone.value(), b"");
        assert_eq!(tombstone.key(), b"deleted_key");

        // Option 2: If you have a special tombstone constructor
        // let tombstone = LogEntry::new_tombstone(b"deleted_key", 1699564800);
        // assert!(tombstone.is_tombstone());
    }

    #[test]
    fn test_tombstone_serialization() {
        // Tombstones should serialize/deserialize correctly
        let mut tombstone = LogEntry::new(b"key_to_delete", b"", 1699564800);
        tombstone.calculate_crc();

        let serialized = tombstone.serialize().unwrap();
        let deserialized = LogEntry::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.key(), b"key_to_delete");
        assert_eq!(deserialized.value(), b"");
        assert!(deserialized.validate_crc());
    }

    #[test]
    fn test_writer_append_tombstone() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.log");

        let mut writer = LogWriter::<Vec<u8>>::new(&log_path).unwrap();

        // Write normal entry
        let mut entry = LogEntry::new(b"key", b"value", 1699564800);
        entry.calculate_crc();
        writer.append(&entry).unwrap();

        // Write tombstone
        let mut tombstone = LogEntry::new(b"key", b"", 1699564801);
        tombstone.calculate_crc();
        let offset = writer.append(&tombstone).unwrap();

        assert!(offset > 0, "Tombstone should be written after first entry");

        writer.sync().unwrap();

        // Verify both entries are in the log
        let reader = LogReader::new(&log_path).unwrap();
        let entries: Vec<_> = reader.iter().unwrap().collect();

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].value(), b"value");
        assert_eq!(entries[1].value(), b""); // tombstone
    }

    #[test]
    fn test_delete_operation_flow() {
        let temp_dir = TempDir::new().unwrap();
        let db = Bitcask::open(temp_dir.path()).unwrap();

        // Put a value
        db.put(b"key", b"value").unwrap();
        assert_eq!(db.get(b"key").unwrap(), Some(b"value".to_vec()));

        // Delete it
        db.delete(b"key").unwrap();

        // Should no longer be accessible
        assert_eq!(db.get(b"key").unwrap(), None);

        // Delete again should be idempotent (no error)
        db.delete(b"key").unwrap();
        assert_eq!(db.get(b"key").unwrap(), None);
    }

    #[test]
    fn test_tombstone_in_log_after_delete() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().to_path_buf();

        {
            let db = Bitcask::open(&db_path).unwrap();
            db.put(b"key", b"value").unwrap();
            db.delete(b"key").unwrap();
            db.sync().unwrap();
        }

        // Read the log directly
        let log_path = db_path.join("000000.log");
        let reader = LogReader::new(&log_path).unwrap();
        let entries: Vec<_> = reader.iter().unwrap().collect();

        // Should have both entries: original and tombstone
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].value(), b"value");
        assert_eq!(entries[1].value(), b""); // tombstone
        assert_eq!(entries[1].key(), b"key"); // same key
    }

    #[test]
    fn test_recovery_with_tombstones() {
        let _ = env_logger::try_init();
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().to_path_buf();

        // Create entries with deletes
        {
            let db = Bitcask::open(&db_path).unwrap();

            // Write some entries
            db.put(b"keep1", b"value1").unwrap();
            db.put(b"delete1", b"value2").unwrap();
            db.put(b"keep2", b"value3").unwrap();
            db.put(b"delete2", b"value4").unwrap();

            // Delete some
            db.delete(b"delete1").unwrap();
            db.delete(b"delete2").unwrap();

            db.sync().unwrap();
        }

        // Reopen and verify deletes were recovered
        {
            let db = Bitcask::open(&db_path).unwrap();

            // Kept entries should exist
            assert_eq!(db.get(b"keep1").unwrap(), Some(b"value1".to_vec())); // FAILS HERE
            assert_eq!(db.get(b"keep2").unwrap(), Some(b"value3".to_vec()));

            // Deleted entries should not exist
            assert_eq!(db.get(b"delete1").unwrap(), None);
            assert_eq!(db.get(b"delete2").unwrap(), None);
        }
    }

    #[test]
    fn test_delete_then_reinsert() {
        let temp_dir = TempDir::new().unwrap();
        let db = Bitcask::open(temp_dir.path()).unwrap();

        println!("put value1");
        // Put, delete, put again
        db.put(b"key", b"value1").unwrap();
        assert_eq!(db.get(b"key").unwrap(), Some(b"value1".to_vec()));

        db.delete(b"key").unwrap();
        assert_eq!(db.get(b"key").unwrap(), None);
        println!("put value2");
        db.put(b"key", b"value2").unwrap();
        assert_eq!(db.get(b"key").unwrap(), Some(b"value2".to_vec()));
    }

    #[test]
    fn test_recovery_with_interleaved_tombstones() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().to_path_buf();

        {
            let db = Bitcask::open(&db_path).unwrap();

            // Complex sequence of operations
            db.put(b"a", b"1").unwrap();
            db.put(b"b", b"2").unwrap();
            db.delete(b"a").unwrap(); // tombstone for a
            db.put(b"c", b"3").unwrap();
            db.put(b"a", b"4").unwrap(); // a is back with new value
            db.delete(b"b").unwrap(); // tombstone for b

            db.sync().unwrap();
        }

        // After recovery
        {
            let db = Bitcask::open(&db_path).unwrap();

            assert_eq!(db.get(b"a").unwrap(), Some(b"4".to_vec())); // reinserted
            assert_eq!(db.get(b"b").unwrap(), None); // deleted
            assert_eq!(db.get(b"c").unwrap(), Some(b"3".to_vec())); // unchanged
        }
    }

    #[test]
    fn test_delete_nonexistent_key() {
        let temp_dir = TempDir::new().unwrap();
        let db = Bitcask::open(temp_dir.path()).unwrap();

        // Deleting non-existent key should not error (idempotent)
        let result = db.delete(b"never_existed");
        assert!(result.is_ok(), "Delete of non-existent key should succeed");

        // Should still not exist
        assert_eq!(db.get(b"never_existed").unwrap(), None);
    }

    #[test]
    fn test_tombstone_size_in_log() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().to_path_buf();

        {
            let db = Bitcask::open(&db_path).unwrap();

            // Write and delete many entries
            for i in 0..10 {
                let key = format!("key{}", i);
                db.put(key.as_bytes(), b"value").unwrap();
            }

            for i in 0..10 {
                let key = format!("key{}", i);
                db.delete(key.as_bytes()).unwrap();
            }

            db.sync().unwrap();
        }

        // Check log file size - should have 20 entries (10 puts + 10 tombstones)
        let log_path = db_path.join("000000.log");
        let reader = LogReader::new(&log_path).unwrap();
        let entry_count = reader.iter().unwrap().count();

        assert_eq!(
            entry_count, 20,
            "Should have original entries plus tombstones"
        );
    }

    #[test]
    fn test_compaction_removes_tombstones() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().to_path_buf();

        let mut db = Bitcask::open(&db_path).unwrap();

        // Create entries and delete some
        for i in 0..10 {
            let key = format!("key{}", i);
            db.put(key.as_bytes(), b"value").unwrap();
        }

        // Delete even-numbered keys
        for i in (0..10).step_by(2) {
            let key = format!("key{}", i);
            db.delete(key.as_bytes()).unwrap();
        }

        db.sync().unwrap();

        // If compaction is implemented
        if db.compact().is_ok() {
            // After compaction, log should only have 5 entries (odd keys)
            // Tombstones and their corresponding entries should be gone

            let log_files: Vec<_> = std::fs::read_dir(&db_path)
                .unwrap()
                .filter_map(|e| e.ok())
                .filter(|e| e.path().extension() == Some("log".as_ref()))
                .collect();

            // Read the compacted log
            let mut total_entries = 0;
            for file in log_files {
                let reader = LogReader::new(&file.path()).unwrap();
                total_entries += reader.iter().unwrap().count();
            }

            // Should have only the 5 remaining keys, no tombstones
            assert!(
                total_entries <= 5,
                "After compaction, should have at most 5 entries, got {}",
                total_entries
            );
        }
    }
}

#[cfg(test)]
mod edge_case_tests {
    use super::*;

    #[test]
    fn test_empty_value_vs_tombstone() {
        let temp_dir = TempDir::new().unwrap();
        let db = Bitcask::open(temp_dir.path()).unwrap();

        // Put an empty value (not a delete)
        db.put(b"empty_value_key", b"").unwrap();

        // Should still exist (empty value != deleted)
        let result = db.get(b"empty_value_key").unwrap();

        // Empty values are allowed:
        assert_eq!(result, Some(Vec::new()));
    }

    #[test]
    fn test_large_key_tombstone() {
        let temp_dir = TempDir::new().unwrap();
        let db = Bitcask::open(temp_dir.path()).unwrap();

        // Large key
        let large_key = vec![0xAB; 1024];

        db.put(&large_key, b"value").unwrap();
        db.delete(&large_key).unwrap();

        // assert_eq!(db.get(&large_key).unwrap(), None);
    }
}

#[cfg(test)]
mod basic_api_tests {
    use super::*;

    #[test]
    fn test_bitcask_open_new() {
        let temp_dir = TempDir::new().unwrap();

        // Should create a new database
        let db = Bitcask::open(temp_dir.path());
        assert!(db.is_ok());

        // Should create necessary files/directories
        let log_file = temp_dir.path().join("000000.log");
        assert!(
            log_file.exists() || temp_dir.path().read_dir().unwrap().count() > 0,
            "Should create at least one log file"
        );
    }

    #[test]
    fn test_bitcask_put_and_get() {
        let temp_dir = TempDir::new().unwrap();
        let mut db = Bitcask::open(temp_dir.path()).unwrap();

        // Put a value
        let result = db.put(b"key1", b"value1");
        assert!(result.is_ok());

        // Get it back
        let value = db.get(b"key1").unwrap();
        assert_eq!(value, Some(b"value1".to_vec()));

        // Non-existent key
        let value = db.get(b"key2").unwrap();
        assert_eq!(value, None);
    }

    #[test]
    fn test_bitcask_update_value() {
        let temp_dir = TempDir::new().unwrap();
        let mut db = Bitcask::open(temp_dir.path()).unwrap();

        // Initial value
        db.put(b"key", b"value1").unwrap();
        assert_eq!(db.get(b"key").unwrap(), Some(b"value1".to_vec()));

        // Update value
        db.put(b"key", b"value2").unwrap();
        assert_eq!(db.get(b"key").unwrap(), Some(b"value2".to_vec()));

        // Old value should not be accessible
        // (though it's still in the log until compaction)
    }

    #[test]
    fn test_bitcask_delete() {
        let temp_dir = TempDir::new().unwrap();
        let mut db = Bitcask::open(temp_dir.path()).unwrap();

        // Put then delete
        db.put(b"key", b"value").unwrap();
        assert!(db.get(b"key").unwrap().is_some());

        let result = db.delete(b"key");
        assert!(result.is_ok());

        // Should no longer exist
        assert_eq!(db.get(b"key").unwrap(), None);

        // Delete non-existent key should be OK (idempotent)
        let result = db.delete(b"key");
        assert!(result.is_ok());
    }

    #[test]
    fn test_bitcask_binary_data() {
        let temp_dir = TempDir::new().unwrap();
        let mut db = Bitcask::open(temp_dir.path()).unwrap();

        // Store binary data
        let key = vec![0x00, 0xFF, 0xDE, 0xAD];
        let value = vec![0xBE, 0xEF, 0xCA, 0xFE];

        db.put(&key, &value).unwrap();
        let retrieved = db.get(&key).unwrap();
        assert_eq!(retrieved, Some(value));
    }

    #[test]
    fn test_bitcask_large_values() {
        let temp_dir = TempDir::new().unwrap();
        let mut db = Bitcask::open(temp_dir.path()).unwrap();

        // 1MB value
        let large_value = vec![0xAB; 1024 * 1024];

        db.put(b"large_key", &large_value).unwrap();
        let retrieved = db.get(b"large_key").unwrap();

        assert_eq!(retrieved, Some(large_value));
    }

    #[test]
    fn test_bitcask_empty_value() {
        let temp_dir = TempDir::new().unwrap();
        let mut db = Bitcask::open(temp_dir.path()).unwrap();

        // Empty values should be allowed
        db.put(b"key", b"").unwrap();
        let value = db.get(b"key").unwrap();
        assert_eq!(value, Some(Vec::new()));
    }

    #[test]
    fn test_bitcask_many_keys() {
        let temp_dir = TempDir::new().unwrap();
        let mut db = Bitcask::open(temp_dir.path()).unwrap();

        // Write many keys
        for i in 0..100 {
            let key = format!("key_{:03}", i);
            let value = format!("value_{:03}", i);
            db.put(key.as_bytes(), value.as_bytes()).unwrap();
        }

        // Read them back in different order
        for i in (0..100).rev() {
            let key = format!("key_{:03}", i);
            let value = format!("value_{:03}", i);
            assert_eq!(db.get(key.as_bytes()).unwrap(), Some(value.into_bytes()));
        }
    }
}

// ============================================
// Persistence Tests
// ============================================

#[cfg(test)]
mod persistence_tests {
    use super::*;

    #[test]
    fn test_bitcask_persistence_across_restart() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().to_path_buf();

        // Write data and close
        {
            let mut db = Bitcask::open(&db_path).unwrap();
            db.put(b"persistent_key", b"persistent_value").unwrap();
            db.sync().unwrap();
            // db dropped here
        }

        // Reopen and verify data is still there
        {
            let db = Bitcask::open(&db_path).unwrap();
            let value = db.get(b"persistent_key").unwrap();
            assert_eq!(value, Some(b"persistent_value".to_vec()));
        }
    }

    #[test]
    fn test_bitcask_sync_behavior() {
        let temp_dir = TempDir::new().unwrap();
        let mut db = Bitcask::open(temp_dir.path()).unwrap();

        // Write without sync
        db.put(b"key1", b"value1").unwrap();

        // Sync should ensure durability
        db.sync().unwrap();

        // Even if we crash here (simulated by drop), data should be safe
        drop(db);

        // Reopen and verify
        let db = Bitcask::open(temp_dir.path()).unwrap();
        assert_eq!(db.get(b"key1").unwrap(), Some(b"value1".to_vec()));
    }

    #[test]
    fn test_bitcask_flush_behavior() {
        let temp_dir = TempDir::new().unwrap();
        let mut db = Bitcask::open(temp_dir.path()).unwrap();

        // Write and flush (but not sync)
        db.put(b"key", b"value").unwrap();
        db.flush().unwrap();

        // Data should be visible to new readers even without sync
        let db2 = Bitcask::open(temp_dir.path()).unwrap();

        // Might or might not see the data depending on implementation
        // This test documents the behavior
    }
}

// ============================================
// Crash Recovery Tests
// ============================================

#[cfg(test)]
mod crash_recovery_tests {
    use crate::bitcask::MemoryLogWriter;

    use super::*;

    #[test]
    fn test_bitcask_recovery_from_clean_shutdown() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().to_path_buf();

        // Create database with data
        {
            let mut db = Bitcask::open(&db_path).unwrap();
            for i in 0..10 {
                let key = format!("key{}", i);
                let value = format!("value{}", i);
                db.put(key.as_bytes(), value.as_bytes()).unwrap();
            }
            db.sync().unwrap();
        }

        // Reopen - should rebuild index from log
        {
            let db = Bitcask::open(&db_path).unwrap();

            // All data should be accessible
            for i in 0..10 {
                let key = format!("key{}", i);
                let value = format!("value{}", i);
                assert_eq!(db.get(key.as_bytes()).unwrap(), Some(value.into_bytes()));
            }
        }
    }

    #[test]
    fn test_bitcask_recovery_with_updates() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().to_path_buf();

        // Create log with updates (same key multiple times)
        {
            let mut db = Bitcask::open(&db_path).unwrap();

            // Write initial values
            for i in 0..5 {
                let key = format!("key{}", i);
                db.put(key.as_bytes(), b"initial").unwrap();
            }

            // Update some values
            for i in 0..3 {
                let key = format!("key{}", i);
                db.put(key.as_bytes(), b"updated").unwrap();
            }

            db.sync().unwrap();
        }

        // Reopen and verify latest values are used
        {
            let db = Bitcask::open(&db_path).unwrap();

            // First 3 should be updated
            for i in 0..3 {
                let key = format!("key{}", i);
                assert_eq!(db.get(key.as_bytes()).unwrap(), Some(b"updated".to_vec()));
            }

            // Last 2 should be initial
            for i in 3..5 {
                let key = format!("key{}", i);
                assert_eq!(db.get(key.as_bytes()).unwrap(), Some(b"initial".to_vec()));
            }
        }
    }

    #[test]
    fn test_bitcask_recovery_with_deletes() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().to_path_buf();

        // Create log with deletes
        {
            let mut db = Bitcask::open(&db_path).unwrap();

            // Write values
            db.put(b"keep", b"value").unwrap();
            db.put(b"delete", b"value").unwrap();

            // Delete one
            db.delete(b"delete").unwrap();

            db.sync().unwrap();
        }

        // Reopen and verify delete was recovered
        {
            let db = Bitcask::open(&db_path).unwrap();
            println!("reopened and reading for key keep");
            assert_eq!(db.get(b"keep").unwrap(), Some(b"value".to_vec()));
            assert_eq!(db.get(b"delete").unwrap(), None);
        }
    }

    #[test]
    fn test_bitcask_recovery_from_partial_write() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().to_path_buf();
        let log_path = db_path.join("000000.log");

        // Create valid entries
        {
            let mut db = Bitcask::open(&db_path).unwrap();
            db.put(b"complete1", b"value1").unwrap();
            db.put(b"complete2", b"value2").unwrap();
            db.sync().unwrap();
        }

        // Simulate partial write (corruption at end of file)
        {
            let mut partial_entry = LogEntry::new(b"partial", b"corrupted", 1699564800);
            partial_entry.calculate_crc();
            let serialized = partial_entry.serialize().unwrap();

            // Append only half of the entry (simulating crash during write)
            use std::fs::OpenOptions;
            use std::io::Write;
            let mut file = OpenOptions::new().append(true).open(&log_path).unwrap();
            file.write_all(&serialized[..serialized.len() / 2]).unwrap();
        }

        // Reopen - should recover gracefully
        {
            let db = Bitcask::open(&db_path).unwrap();

            // Complete entries should be recovered
            assert_eq!(db.get(b"complete1").unwrap(), Some(b"value1".to_vec()));
            assert_eq!(db.get(b"complete2").unwrap(), Some(b"value2".to_vec()));

            // Partial entry should not exist
            assert_eq!(db.get(b"partial").unwrap(), None);
        }
    }

    #[test]
    fn test_bitcask_recovery_from_corrupted_entry() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().to_path_buf();

        // Create some valid entries
        {
            let mut db = Bitcask::open(&db_path).unwrap();
            db.put(b"before", b"value").unwrap();
            db.sync().unwrap();
        }

        // Manually corrupt an entry in the middle
        {
            let log_path = db_path.join("000000.log");
            let mut data = fs::read(&log_path).unwrap();

            // Flip some bits in the middle
            if data.len() > 20 {
                data[15] ^= 0xFF;
                data[16] ^= 0xFF;
            }

            fs::write(&log_path, data).unwrap();
        }

        // Write more valid data after corruption
        {
            let mut writer = MemoryLogWriter::new(&db_path.join("000000.log")).unwrap();
            let mut entry = LogEntry::new(b"after", b"value", 1699564900);
            entry.calculate_crc();
            writer.append(&entry).unwrap();
            writer.sync().unwrap();
        }

        // Reopen - should handle corruption gracefully
        {
            let result = Bitcask::open(&db_path);

            // Depending on implementation, might:
            // 1. Skip corrupted entry and continue
            // 2. Stop at corruption point
            // 3. Fail to open

            // Document your choice with assertions
            if let Ok(db) = result {
                // If it opens, check what was recovered
                let before = db.get(b"before").unwrap();
                let after = db.get(b"after").unwrap();

                println!("Recovery behavior: before={:?}, after={:?}", before, after);
            } else {
                println!("Database failed to open with corruption");
            }
        }
    }

    #[test]
    fn test_bitcask_recovery_multiple_log_files() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().to_path_buf();

        // Create multiple log files with rotation
        {
            // Use with_options for rotation
            let db = Bitcask::open_with_options(&db_path, BitcaskOptions { size: 500 }).unwrap(); // Small size to force rotation

            // Write enough data to span multiple files
            for i in 0..20 {
                let key = format!("key{:02}", i);
                let value = vec![0xFF; 50]; // Each entry ~70 bytes with overhead
                db.put(key.as_bytes(), &value).unwrap();
            }

            db.sync().unwrap();
        }

        // Verify multiple log files exist
        let log_files: Vec<_> = fs::read_dir(&db_path)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension() == Some("log".as_ref()))
            .collect();

        assert!(log_files.len() > 1, "Should have multiple log files");

        // Reopen - should scan all log files
        {
            let db = Bitcask::open(&db_path).unwrap();

            // All keys should be accessible
            for i in 0..20 {
                let key = format!("key{:02}", i);
                assert!(
                    db.get(key.as_bytes()).unwrap().is_some(),
                    "Key {} should exist after recovery",
                    key
                );
            }
        }
    }

    #[test]
    fn test_bitcask_recovery_preserves_file_id() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().to_path_buf();

        // Create database with rotation
        {
            let db = Bitcask::open_with_options(&db_path, BitcaskOptions { size: 500 }).unwrap();

            // Force multiple files
            for i in 0..30 {
                let value = vec![0xAB; 40];
                db.put(format!("key{}", i).as_bytes(), &value).unwrap();
            }

            db.sync().unwrap();
        }

        // Count log files before restart
        let files_before: Vec<_> = fs::read_dir(&db_path)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension() == Some("log".as_ref()))
            .map(|e| e.path())
            .collect();

        let last_file_id_before = files_before.len() - 1;

        // Reopen
        {
            let db = Bitcask::open_with_options(&db_path, BitcaskOptions { size: 500 }).unwrap();

            // Write more data
            db.put(b"after_recovery", b"value").unwrap();
            db.sync().unwrap();
        }

        // Should continue from last file ID, not restart at 0
        let files_after: Vec<_> = fs::read_dir(&db_path)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension() == Some("log".as_ref()))
            .collect();

        println!("{} >= {}", files_after.len(), files_before.len());

        assert!(
            files_after.len() >= files_before.len(),
            "Should preserve or increment file count"
        );
    }
}

// // ============================================
// // Edge Cases and Error Handling
// // ============================================

// #[cfg(test)]
// mod edge_case_tests {
//     use super::*;

//     #[test]
//     fn test_bitcask_empty_key() {
//         let temp_dir = TempDir::new().unwrap();
//         let mut db = Bitcask::open(temp_dir.path()).unwrap();

//         // Empty keys might be allowed or rejected
//         // Document your choice
//         let result = db.put(b"", b"value");

//         if result.is_ok() {
//             // If allowed, should be retrievable
//             assert_eq!(db.get(b"").unwrap(), Some(b"value".to_vec()));
//         } else {
//             // If rejected, should be consistent
//             assert!(matches!(result.unwrap_err(), StorageError::InvalidKey(_)));
//         }
//     }

//     #[test]
//     fn test_bitcask_reopen_same_process() {
//         let temp_dir = TempDir::new().unwrap();
//         let db_path = temp_dir.path().to_path_buf();

//         let db1 = Bitcask::open(&db_path).unwrap();

//         // Try to open again in same process
//         let result = Bitcask::open(&db_path);

//         // Document whether multiple opens are allowed
//         if result.is_ok() {
//             println!("Implementation allows multiple opens in same process");
//         } else {
//             println!("Implementation prevents multiple opens in same process");
//         }
//     }

//     #[test]
//     fn test_bitcask_readonly_directory() {
//         let temp_dir = TempDir::new().unwrap();
//         let db_path = temp_dir.path().to_path_buf();

//         // Create database
//         {
//             let mut db = Bitcask::open(&db_path).unwrap();
//             db.put(b"key", b"value").unwrap();
//             db.sync().unwrap();
//         }

//         // Make directory read-only
//         #[cfg(unix)]
//         {
//             use std::os::unix::fs::PermissionsExt;
//             let permissions = fs::Permissions::from_mode(0o555);
//             fs::set_permissions(&db_path, permissions).unwrap();

//             // Try to open for writing
//             let result = Bitcask::open(&db_path);

//             // Should fail or open in read-only mode
//             if let Ok(mut db) = result {
//                 let write_result = db.put(b"new_key", b"new_value");
//                 assert!(write_result.is_err(), "Writes should fail on read-only directory");
//             }

//             // Restore permissions for cleanup
//             let permissions = fs::Permissions::from_mode(0o755);
//             fs::set_permissions(&db_path, permissions).unwrap();
//         }
//     }
// }

// // ============================================
// // API Completeness Tests
// // ============================================

// #[cfg(test)]
// mod api_completeness_tests {
//     use super::*;

//     #[test]
//     fn test_bitcask_list_keys() {
//         let temp_dir = TempDir::new().unwrap();
//         let mut db = Bitcask::open(temp_dir.path()).unwrap();

//         // Add some keys
//         db.put(b"key1", b"value1").unwrap();
//         db.put(b"key2", b"value2").unwrap();
//         db.put(b"key3", b"value3").unwrap();

//         // If list_keys is implemented
//         if let Ok(keys) = db.list_keys() {
//             assert_eq!(keys.len(), 3);
//             assert!(keys.contains(&b"key1".to_vec()));
//             assert!(keys.contains(&b"key2".to_vec()));
//             assert!(keys.contains(&b"key3".to_vec()));
//         }
//     }

//     #[test]
//     fn test_bitcask_stats() {
//         let temp_dir = TempDir::new().unwrap();
//         let mut db = Bitcask::open(temp_dir.path()).unwrap();

//         // Write some data
//         for i in 0..10 {
//             db.put(format!("key{}", i).as_bytes(), b"value").unwrap();
//         }

//         // If stats are implemented
//         if let Ok(stats) = db.stats() {
//             assert_eq!(stats.key_count, 10);
//             assert!(stats.disk_size > 0);
//             assert!(stats.dead_bytes >= 0); // No updates yet, so no dead bytes
//         }
//     }

//     #[test]
//     fn test_bitcask_merge() {
//         let temp_dir = TempDir::new().unwrap();
//         let db_path = temp_dir.path().to_path_buf();

//         let mut db = Bitcask::open(&db_path).unwrap();

//         // Create garbage by updating same keys
//         for _ in 0..5 {
//             for i in 0..10 {
//                 db.put(format!("key{}", i).as_bytes(), b"value").unwrap();
//             }
//         }

//         db.sync().unwrap();

//         // Get size before merge
//         let size_before = get_directory_size(&db_path);

//         // Run merge/compaction if implemented
//         if db.merge().is_ok() {
//             let size_after = get_directory_size(&db_path);

//             // Should be smaller after removing dead entries
//             assert!(size_after < size_before,
//                 "Merge should reduce size: {} -> {}", size_before, size_after);

//             // All keys should still be accessible
//             for i in 0..10 {
//                 assert!(db.get(format!("key{}", i).as_bytes()).unwrap().is_some());
//             }
//         }
//     }

//     fn get_directory_size(path: &Path) -> u64 {
//         fs::read_dir(path)
//             .unwrap()
//             .filter_map(|e| e.ok())
//             .filter_map(|e| e.metadata().ok())
//             .map(|m| m.len())
//             .sum()
//     }
// }

// // ============================================
// // Performance and Stress Tests
// // ============================================

// #[cfg(test)]
// mod performance_tests {
//     use super::*;
//     use std::time::Instant;

//     #[test]
//     #[ignore] // Run with --ignored
//     fn test_bitcask_write_performance() {
//         let temp_dir = TempDir::new().unwrap();
//         let mut db = Bitcask::open(temp_dir.path()).unwrap();

//         let value = vec![0xAB; 1000]; // 1KB values
//         let iterations = 10_000;

//         let start = Instant::now();

//         for i in 0..iterations {
//             let key = format!("key_{:06}", i);
//             db.put(key.as_bytes(), &value).unwrap();
//         }

//         db.sync().unwrap();
//         let elapsed = start.elapsed();

//         let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();
//         let mb_per_sec = (iterations * 1000) as f64 / 1_048_576.0 / elapsed.as_secs_f64();

//         println!("Write performance: {:.0} ops/sec, {:.2} MB/sec", ops_per_sec, mb_per_sec);

//         // Should achieve reasonable performance
//         assert!(ops_per_sec > 1000.0, "Write performance too low");
//     }

//     #[test]
//     #[ignore] // Run with --ignored
//     fn test_bitcask_read_performance() {
//         let temp_dir = TempDir::new().unwrap();
//         let mut db = Bitcask::open(temp_dir.path()).unwrap();

//         // Prepare data
//         let value = vec![0xCD; 1000];
//         for i in 0..1000 {
//             db.put(format!("key_{:04}", i).as_bytes(), &value).unwrap();
//         }
//         db.sync().unwrap();

//         // Measure random reads
//         let iterations = 10_000;
//         let start = Instant::now();

//         for i in 0..iterations {
//             let key_idx = (i * 7) % 1000; // Pseudo-random pattern
//             let key = format!("key_{:04}", key_idx);
//             let _ = db.get(key.as_bytes()).unwrap();
//         }

//         let elapsed = start.elapsed();
//         let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

//         println!("Read performance: {:.0} ops/sec", ops_per_sec);

//         // Reads should be very fast (in-memory index)
//         assert!(ops_per_sec > 10000.0, "Read performance too low");
//     }

//     #[test]
//     #[ignore] // Run with --ignored
//     fn test_bitcask_recovery_performance() {
//         let temp_dir = TempDir::new().unwrap();
//         let db_path = temp_dir.path().to_path_buf();

//         // Create large database
//         {
//             let mut db = Bitcask::open(&db_path).unwrap();
//             for i in 0..10_000 {
//                 let key = format!("key_{:06}", i);
//                 let value = format!("value_{:06}", i);
//                 db.put(key.as_bytes(), value.as_bytes()).unwrap();
//             }
//             db.sync().unwrap();
//         }

//         // Measure recovery time
//         let start = Instant::now();
//         {
//             let _db = Bitcask::open(&db_path).unwrap();
//         }
//         let elapsed = start.elapsed();

//         println!("Recovery time for 10,000 entries: {:?}", elapsed);

//         // Recovery should be reasonably fast
//         assert!(elapsed.as_secs() < 5, "Recovery too slow");
//     }
// }
