// tests/concurrency.rs
// Comprehensive tests for thread-safe Bitcask implementation

use crate::bitcask::Bitcask;
use std::collections::HashSet;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

// ============================================
// Basic Thread Safety Tests
// ============================================

#[cfg(test)]
mod basic_concurrency_tests {
    use super::*;

    #[test]
    fn test_concurrent_bitcask_creation() {
        let temp_dir = TempDir::new().unwrap();

        // Should be able to create thread-safe wrapper
        let db = Bitcask::open(temp_dir.path()).unwrap();

        // Should be Clone-able for sharing across threads
        let db2 = db.clone();

        // Both should point to same underlying database
        db.put(b"key", b"value").unwrap();
        assert_eq!(db2.get(b"key").unwrap(), Some(b"value".to_vec()));
    }

    #[test]
    fn test_send_and_sync_traits() {
        // Verify that Bitcask implements Send + Sync
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}

        assert_send::<Bitcask>();
        assert_sync::<Bitcask>();
    }

    #[test]
    fn test_concurrent_reads() {
        let temp_dir = TempDir::new().unwrap();
        let db = Arc::new(Bitcask::open(temp_dir.path()).unwrap());

        // Prepare test data
        for i in 0..100 {
            db.put(
                format!("key{}", i).as_bytes(),
                format!("value{}", i).as_bytes(),
            )
            .unwrap();
        }

        // Spawn multiple reader threads
        let mut handles = vec![];
        for thread_id in 0..10 {
            let db = Arc::clone(&db);

            let handle = thread::spawn(move || {
                for i in 0..100 {
                    let key = format!("key{}", i);
                    let expected = format!("value{}", i);

                    let value = db.get(key.as_bytes()).unwrap();
                    assert_eq!(value, Some(expected.into_bytes()));
                }
                thread_id
            });

            handles.push(handle);
        }

        // All threads should complete successfully
        for handle in handles {
            let thread_id = handle.join().unwrap();
            println!("Reader thread {} completed", thread_id);
        }
    }

    #[test]
    fn test_concurrent_writes() {
        let temp_dir = TempDir::new().unwrap();
        let db = Arc::new(Bitcask::open(temp_dir.path()).unwrap());

        let mut handles = vec![];

        // Each thread writes its own keys
        for thread_id in 0..10 {
            let db = Arc::clone(&db);

            let handle = thread::spawn(move || {
                for i in 0..100 {
                    let key = format!("thread{}_key{}", thread_id, i);
                    let value = format!("thread{}_value{}", thread_id, i);

                    db.put(key.as_bytes(), value.as_bytes()).unwrap();
                }
            });

            handles.push(handle);
        }

        // Wait for all writers
        for handle in handles {
            handle.join().unwrap();
        }

        // Verify all data was written
        for thread_id in 0..10 {
            for i in 0..100 {
                let key = format!("thread{}_key{}", thread_id, i);
                let expected = format!("thread{}_value{}", thread_id, i);

                let value = db.get(key.as_bytes()).unwrap();
                assert_eq!(value, Some(expected.into_bytes()));
            }
        }
    }

    #[test]
    fn test_concurrent_read_write_mix() {
        let temp_dir = TempDir::new().unwrap();
        let db = Arc::new(Bitcask::open(temp_dir.path()).unwrap());

        // Barrier to synchronize thread start
        let barrier = Arc::new(Barrier::new(20));
        let mut handles = vec![];

        // 10 writer threads
        for thread_id in 0..10 {
            let db = Arc::clone(&db);
            let barrier = Arc::clone(&barrier);

            let handle = thread::spawn(move || {
                barrier.wait();

                for i in 0..50 {
                    let key = format!("key{}", i);
                    let value = format!("writer{}_value{}", thread_id, i);
                    db.put(key.as_bytes(), value.as_bytes()).unwrap();

                    // Small delay to interleave operations
                    thread::sleep(Duration::from_micros(10));
                }
            });
            handles.push(handle);
        }

        // 10 reader threads
        for thread_id in 0..10 {
            let db = Arc::clone(&db);
            let barrier = Arc::clone(&barrier);

            let handle = thread::spawn(move || {
                barrier.wait();

                for _ in 0..100 {
                    let key_id = thread_id * 5; // Read subset of keys
                    let key = format!("key{}", key_id);

                    // Value might not exist yet or might be from any writer
                    let _ = db.get(key.as_bytes());

                    thread::sleep(Duration::from_micros(10));
                }
            });
            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        // Final verification - all keys should have some value
        for i in 0..50 {
            let key = format!("key{}", i);
            assert!(db.get(key.as_bytes()).unwrap().is_some());
        }
    }
}

// ============================================
// Race Condition Tests
// ============================================

#[cfg(test)]
mod race_condition_tests {
    use super::*;

    #[test]
    fn test_concurrent_updates_same_key() {
        let temp_dir = TempDir::new().unwrap();
        let db = Arc::new(Bitcask::open(temp_dir.path()).unwrap());

        let barrier = Arc::new(Barrier::new(10));
        let mut handles = vec![];

        // 10 threads all updating the same key
        for thread_id in 0..10 {
            let db = Arc::clone(&db);
            let barrier = Arc::clone(&barrier);

            let handle = thread::spawn(move || {
                barrier.wait(); // All threads start together

                for i in 0..100 {
                    let value = format!("thread{}_iteration{}", thread_id, i);
                    db.put(b"contested_key", value.as_bytes()).unwrap();
                }
            });
            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        // Should have some value (last writer wins)
        let final_value = db.get(b"contested_key").unwrap();
        assert!(final_value.is_some());

        // The value should be from one of the threads' last iteration
        let value_str = String::from_utf8(final_value.unwrap()).unwrap();
        assert!(value_str.contains("iteration99"));
    }

    #[test]
    fn test_concurrent_delete_and_put() {
        let temp_dir = TempDir::new().unwrap();
        let db = Arc::new(Bitcask::open(temp_dir.path()).unwrap());

        db.put(b"key", b"initial").unwrap();

        let barrier = Arc::new(Barrier::new(3));

        // Thread 1: Deleter
        let db1 = Arc::clone(&db);
        let barrier1 = Arc::clone(&barrier);
        let deleter = thread::spawn(move || {
            barrier1.wait();
            for _ in 0..100 {
                db1.delete(b"key").unwrap();
                thread::sleep(Duration::from_micros(10));
            }
        });

        // Thread 2: Putter
        let db2 = Arc::clone(&db);
        let barrier2 = Arc::clone(&barrier);
        let putter = thread::spawn(move || {
            barrier2.wait();
            for i in 0..100 {
                db2.put(b"key", format!("value{}", i).as_bytes()).unwrap();
                thread::sleep(Duration::from_micros(10));
            }
        });

        // Thread 3: Reader
        let db3 = Arc::clone(&db);
        let barrier3 = Arc::clone(&barrier);
        let reader = thread::spawn(move || {
            barrier3.wait();
            let mut seen_values = HashSet::new();

            for _ in 0..200 {
                match db3.get(b"key").unwrap() {
                    Some(value) => {
                        seen_values.insert(value);
                    }
                    None => {
                        // Key was deleted, this is OK
                    }
                }
                thread::sleep(Duration::from_micros(5));
            }
            seen_values
        });

        deleter.join().unwrap();
        putter.join().unwrap();
        let seen = reader.join().unwrap();

        // Should have seen various states
        println!("Reader saw {} different values", seen.len());
        assert!(seen.len() > 0, "Reader should see some values");
    }

    #[test]
    fn test_index_consistency_under_concurrent_access() {
        let temp_dir = TempDir::new().unwrap();
        let db = Arc::new(Bitcask::open(temp_dir.path()).unwrap());

        let barrier = Arc::new(Barrier::new(5));
        let mut handles = vec![];

        // Writers adding keys
        for thread_id in 0..3 {
            let db = Arc::clone(&db);
            let barrier = Arc::clone(&barrier);

            let handle = thread::spawn(move || {
                barrier.wait();
                for i in 0..100 {
                    let key = format!("t{}_k{}", thread_id, i);
                    db.put(key.as_bytes(), b"value").unwrap();
                }
            });
            handles.push(handle);
        }

        // Readers checking consistency
        for _ in 0..2 {
            let db = Arc::clone(&db);
            let barrier = Arc::clone(&barrier);

            let handle = thread::spawn(move || {
                barrier.wait();

                for _ in 0..100 {
                    // If we can get a key, we should always get the same value
                    let key = b"t0_k0";
                    if let Some(value1) = db.get(key).unwrap() {
                        // Read again immediately
                        let value2 = db.get(key).unwrap();
                        assert_eq!(
                            Some(value1),
                            value2,
                            "Consecutive reads should be consistent"
                        );
                    }

                    thread::sleep(Duration::from_micros(10));
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }
}

// ============================================
// Performance Under Concurrency Tests
// ============================================

#[cfg(test)]
mod concurrent_performance_tests {
    use super::*;

    #[test]
    #[ignore] // Run with --ignored
    fn test_read_scalability() {
        let temp_dir = TempDir::new().unwrap();
        let db = Arc::new(Bitcask::open(temp_dir.path()).unwrap());

        // Prepare data
        for i in 0..1000 {
            db.put(format!("key{}", i).as_bytes(), &vec![0u8; 1000])
                .unwrap();
        }

        // Measure single-threaded performance
        let start = Instant::now();
        for _ in 0..10000 {
            let key_id = fastrand::usize(..1000);
            db.get(format!("key{}", key_id).as_bytes()).unwrap();
        }
        let single_threaded_time = start.elapsed();

        // Measure multi-threaded performance
        let thread_counts = vec![2, 4, 8];

        for num_threads in thread_counts {
            let start = Instant::now();
            let mut handles = vec![];

            for _ in 0..num_threads {
                let db = Arc::clone(&db);
                let handle = thread::spawn(move || {
                    for _ in 0..10000 / num_threads {
                        let key_id = fastrand::usize(..1000);
                        db.get(format!("key{}", key_id).as_bytes()).unwrap();
                    }
                });
                handles.push(handle);
            }

            for handle in handles {
                handle.join().unwrap();
            }

            let multi_threaded_time = start.elapsed();
            let speedup = single_threaded_time.as_secs_f64() / multi_threaded_time.as_secs_f64();

            println!("{} threads: {:.2}x speedup", num_threads, speedup);

            // Should see some speedup with multiple threads
            assert!(speedup > 0.8, "Multi-threading shouldn't make things worse");
        }
    }

    #[test]
    #[ignore] // Run with --ignored
    fn test_write_contention() {
        let temp_dir = TempDir::new().unwrap();
        let db = Arc::new(Bitcask::open(temp_dir.path()).unwrap());

        let thread_counts = vec![1, 2, 4, 8];

        for num_threads in thread_counts {
            let start = Instant::now();
            let mut handles = vec![];
            let operations_per_thread = 1000;

            for thread_id in 0..num_threads {
                let db = Arc::clone(&db);
                let handle = thread::spawn(move || {
                    for i in 0..operations_per_thread {
                        let key = format!("t{}_k{}", thread_id, i);
                        db.put(key.as_bytes(), b"value").unwrap();
                    }
                });
                handles.push(handle);
            }

            for handle in handles {
                handle.join().unwrap();
            }

            let elapsed = start.elapsed();
            let total_ops = num_threads * operations_per_thread;
            let ops_per_sec = total_ops as f64 / elapsed.as_secs_f64();

            println!("{} threads: {:.0} ops/sec", num_threads, ops_per_sec);
        }
    }
}

// ============================================
// Lock-Free Optimization Tests
// ============================================

#[cfg(test)]
mod lock_free_tests {
    use super::*;

    #[test]
    fn test_lock_free_reads_if_implemented() {
        // This test checks if lock-free reads are implemented
        let temp_dir = TempDir::new().unwrap();
        let db = Arc::new(Bitcask::open(temp_dir.path()).unwrap());

        // Write initial data
        for i in 0..100 {
            db.put(format!("key{}", i).as_bytes(), b"value").unwrap();
        }

        // Try to detect if reads block each other
        let barrier = Arc::new(Barrier::new(10));
        let mut handles = vec![];

        for _ in 0..10 {
            let db = Arc::clone(&db);
            let barrier = Arc::clone(&barrier);

            let handle = thread::spawn(move || {
                barrier.wait();
                let start = Instant::now();

                // Each thread reads same keys
                for i in 0..100 {
                    db.get(format!("key{}", i).as_bytes()).unwrap();
                }

                start.elapsed()
            });
            handles.push(handle);
        }

        let times: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // If reads are lock-free, times should be similar
        let max_time = times.iter().max().unwrap();
        let min_time = times.iter().min().unwrap();

        let variance = max_time.as_secs_f64() / min_time.as_secs_f64();

        if variance < 1.5 {
            println!(
                "Reads appear to be lock-free (low variance: {:.2})",
                variance
            );
        } else {
            println!(
                "Reads appear to be locking (high variance: {:.2})",
                variance
            );
        }
    }

    #[test]
    fn test_epoch_based_memory_reclamation_if_implemented() {
        // Test for advanced lock-free memory management
        let temp_dir = TempDir::new().unwrap();
        let db = Arc::new(Bitcask::open(temp_dir.path()).unwrap());

        // Continuously update same keys while reading
        let running = Arc::new(std::sync::atomic::AtomicBool::new(true));

        // Writer thread
        let db_writer = Arc::clone(&db);
        let running_writer = Arc::clone(&running);
        let writer = thread::spawn(move || {
            let mut iteration = 0;
            while running_writer.load(std::sync::atomic::Ordering::Relaxed) {
                for i in 0..10 {
                    let key = format!("key{}", i);
                    let value = format!("value{}", iteration);
                    db_writer.put(key.as_bytes(), value.as_bytes()).unwrap();
                }
                iteration += 1;
                thread::sleep(Duration::from_millis(1));
            }
            iteration
        });

        // Reader threads
        let mut readers = vec![];
        for _ in 0..4 {
            let db_reader = Arc::clone(&db);
            let running_reader = Arc::clone(&running);

            let reader = thread::spawn(move || {
                let mut read_count = 0;
                while running_reader.load(std::sync::atomic::Ordering::Relaxed) {
                    for i in 0..10 {
                        let key = format!("key{}", i);
                        db_reader.get(key.as_bytes()).unwrap();
                        read_count += 1;
                    }
                }
                read_count
            });
            readers.push(reader);
        }

        // Let it run for a bit
        thread::sleep(Duration::from_millis(100));

        // Stop all threads
        running.store(false, std::sync::atomic::Ordering::Relaxed);

        let write_iterations = writer.join().unwrap();
        let total_reads: usize = readers.into_iter().map(|r| r.join().unwrap()).sum();

        println!(
            "Completed {} write iterations and {} reads",
            write_iterations, total_reads
        );

        // Should complete without memory leaks or crashes
        assert!(write_iterations > 10);
        assert!(total_reads > 1000);
    }
}

// ============================================
// Deadlock Detection Tests
// ============================================

#[cfg(test)]
mod deadlock_tests {
    use super::*;

    #[test]
    fn test_no_deadlock_on_recursive_operations() {
        let temp_dir = TempDir::new().unwrap();
        let db = Bitcask::open(temp_dir.path()).unwrap();

        // This might cause issues with poor locking strategy
        db.put(b"key1", b"value1").unwrap();

        // Get that triggers another get internally (if implemented poorly)
        let value = db.get(b"key1").unwrap();
        assert_eq!(value, Some(b"value1".to_vec()));

        // Should complete without deadlock
    }

    #[test]
    fn test_no_deadlock_with_multiple_operations() {
        let temp_dir = TempDir::new().unwrap();
        let db = Arc::new(Bitcask::open(temp_dir.path()).unwrap());

        let mut handles = vec![];

        // Thread doing put->get->delete sequence
        for thread_id in 0..10 {
            let db = Arc::clone(&db);
            let handle = thread::spawn(move || {
                for i in 0..100 {
                    let key = format!("key_{}_{}", thread_id, i);

                    // Complex operation sequence
                    db.put(key.as_bytes(), b"value").unwrap();
                    db.get(key.as_bytes()).unwrap();
                    db.delete(key.as_bytes()).unwrap();
                }
            });
            handles.push(handle);
        }

        // Should complete without deadlock
        for handle in handles {
            handle.join().unwrap();
        }
    }
}
