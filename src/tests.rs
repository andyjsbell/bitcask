// tests/data_structures.rs
// These tests define the expected behavior for LogEntry and LogPointer

use crate::bitcask::{LogEntry, LogPointer, LogWriter, StorageError};
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

        // Should be exactly 24 bytes (4 + 8 + 4 + 8)
        // This is important for memory calculations
        assert_eq!(
            pointer_size, 24,
            "LogPointer should be exactly 24 bytes for memory efficiency"
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
        let size = serialized.len() as u32;

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
            let size = serialized.len() as u32;

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

            let expected_size = entry.serialize().unwrap().len() as u32;

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
        // This is expected and good for performance
        let metadata = fs::metadata(&log_path).unwrap();

        // File size could be 0 (buffered) or serialized_size (unbuffered)
        // Both are acceptable, but we need to handle both cases

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
