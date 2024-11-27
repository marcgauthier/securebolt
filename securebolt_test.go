package securebolt

import (
	"bytes"
	"fmt"
	"os"
	"sync"
	"testing"
)

func TestSecureBolt(t *testing.T) {
	filename := "test_concurrent.db"
	fileMode := os.FileMode(0600)
	password := "secure-test-password"
	bucketName := []byte("ConcurrentBucket")

	defer os.Remove(filename)

	// Open SecureBolt database
	db, err := Open(filename, fileMode, []byte(password))
	if err != nil {
		t.Fatalf("Failed to open SecureBolt: %v", err)
	}
	defer db.Close()

	// Initialize the bucket
	err = db.Update(func(tx *SecureTx) error {
		_, err := tx.CreateBucketIfNotExists(bucketName)
		return err
	})
	if err != nil {
		t.Fatalf("Failed to create bucket: %v", err)
	}

	// Constants for testing
	const goroutines = 10
	const writesPerGoroutine = 100

	// Concurrent writes
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for retry := 0; retry < 3; retry++ { // Retry mechanism
				err := db.Update(func(tx *SecureTx) error {
					secureBucket, err := tx.Bucket(bucketName)
					if err != nil {
						return err
					}

					for j := 0; j < writesPerGoroutine; j++ {
						key := []byte(fmt.Sprintf("goroutine-%d-key-%d", gid, j))
						value := []byte(fmt.Sprintf("value-%d-%d", gid, j))
						if err := secureBucket.Put(key, value); err != nil {
							return fmt.Errorf("failed to put key %s: %v", key, err)
						}
					}
					return nil
				})
				if err == nil {
					break
				}
				t.Logf("Retrying write for goroutine %d: %v", gid, err)
			}
		}(i)
	}
	wg.Wait()

	// Sequential validation phase
	err = db.View(func(tx *SecureTx) error {
		secureBucket, err := tx.Bucket(bucketName)
		if err != nil {
			return err
		}

		for i := 0; i < goroutines; i++ {
			for j := 0; j < writesPerGoroutine; j++ {
				key := []byte(fmt.Sprintf("goroutine-%d-key-%d", i, j))
				expectedValue := []byte(fmt.Sprintf("value-%d-%d", i, j))
				retrievedValue, err := secureBucket.Get(key)
				if err != nil {
					return fmt.Errorf("failed to get key %s: %v", key, err)
				}
				if !bytes.Equal(retrievedValue, expectedValue) {
					return fmt.Errorf("value mismatch for key %s: got %s, expected %s", key, retrievedValue, expectedValue)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Sequential validation failed: %v", err)
	}

	// Concurrent reads
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			err := db.View(func(tx *SecureTx) error {
				secureBucket, err := tx.Bucket(bucketName)
				if err != nil {
					return err
				}

				for j := 0; j < writesPerGoroutine; j++ {
					key := []byte(fmt.Sprintf("goroutine-%d-key-%d", gid, j))
					expectedValue := []byte(fmt.Sprintf("value-%d-%d", gid, j))
					retrievedValue, err := secureBucket.Get(key)
					if err != nil {
						t.Errorf("Failed to get key %s: %v", key, err)
						continue
					}
					if !bytes.Equal(retrievedValue, expectedValue) {
						t.Errorf("Value mismatch for key %s: got %s, expected %s", key, retrievedValue, expectedValue)
					}
				}
				return nil
			})
			if err != nil {
				t.Errorf("Read transaction failed for goroutine %d: %v", gid, err)
			}
		}(i)
	}
	wg.Wait()
}
