package securebolt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"

	"github.com/awnumar/memguard"
	"go.etcd.io/bbolt"
	"golang.org/x/crypto/argon2"
)

// SecureBolt wraps a bbolt.DB and manages encryption for SecureBucket.
type SecureBolt struct {
	db      *bbolt.DB
	keyLock *memguard.LockedBuffer // Encryption key securely stored in memguard
	aead    cipher.AEAD            // AES-GCM cipher for encryption/decryption
	salt    []byte                 // Salt used for key derivation
	mu      sync.RWMutex           // Mutex for thread safety
}

func init() {
	memguard.CatchInterrupt()
}

func Open(filename string, mode fs.FileMode, password []byte) (*SecureBolt, error) {

	// Validate inputs
	if filename == "" {
		return nil, errors.New("filename cannot be empty")
	}
	if len(password) == 0 {
		return nil, errors.New("password cannot be empty")
	}

	var isNewDB bool
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		isNewDB = true
	}

	// Open the BoltDB file with the provided file mode
	db, err := bbolt.Open(filename, mode, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open BoltDB: %w", err)
	}

	var salt []byte

	if isNewDB {
		// Generate a new random salt
		salt = make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			db.Close()
			return nil, fmt.Errorf("failed to generate salt: %w", err)
		}

		// Store the salt in a dedicated bucket
		err = db.Update(func(tx *bbolt.Tx) error {
			b, err := tx.CreateBucketIfNotExists([]byte("securebolt_meta"))
			if err != nil {
				return err
			}
			return b.Put([]byte("salt"), salt)
		})
		if err != nil {
			db.Close()
			return nil, fmt.Errorf("failed to store salt: %w", err)
		}
	} else {
		// Retrieve the salt from the database
		err = db.View(func(tx *bbolt.Tx) error {
			b := tx.Bucket([]byte("securebolt_meta"))
			if b == nil {
				return errors.New("metadata bucket not found")
			}
			s := b.Get([]byte("salt"))
			if s == nil {
				return errors.New("salt not found in metadata")
			}
			salt = append([]byte{}, s...) // Copy the salt as BoltDB reuses buffers
			return nil
		})
		if err != nil {
			db.Close()
			return nil, fmt.Errorf("failed to retrieve salt: %w", err)
		}
	}

	// Derive encryption key using Argon2id
	// Use password directly as []byte
	keyLock, err := deriveKey(password, salt)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}
	memguard.WipeBytes(password) // Securely erase the password

	// Melt the key to access its bytes
	keyLock.Melt()
	defer keyLock.Freeze()

	// Initialize AES-GCM
	block, err := aes.NewCipher(keyLock.Bytes())
	if err != nil {
		keyLock.Destroy()
		db.Close()
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		keyLock.Destroy()
		db.Close()
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Create and return the SecureBolt instance
	return &SecureBolt{
		db:      db,
		aead:    aead,
		keyLock: keyLock,
		salt:    salt,
	}, nil
}

func deriveKey(password, salt []byte) (*memguard.LockedBuffer, error) {
	const time = 3
	const memory = 128 * 1024
	const threads = 4
	const keyLength = 32

	keyLock := memguard.NewBuffer(keyLength)
	keyLock.Melt()
	defer keyLock.Freeze()

	derivedKey := argon2.IDKey(password, salt, time, memory, threads, keyLength)
	copy(keyLock.Bytes(), derivedKey)
	memguard.WipeBytes(derivedKey) // Ensure the derivedKey slice is wiped
	return keyLock, nil
}

// Close securely destroys the encryption key and closes the database.
func (s *SecureBolt) Close() error {
	s.keyLock.Destroy() // Securely destroy the encryption key
	return s.db.Close()
}

// SecureTx wraps a bbolt.Tx and provides methods to access SecureBucket.
type SecureTx struct {
	tx      *bbolt.Tx
	aead    cipher.AEAD
	keyLock *memguard.LockedBuffer
}

func (s *SecureBolt) View(fn func(tx *SecureTx) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.db.View(func(tx *bbolt.Tx) error {
		return fn(&SecureTx{
			tx:      tx,
			aead:    s.aead,
			keyLock: s.keyLock, // Pass keyLock
		})
	})
}

func (s *SecureBolt) Update(fn func(tx *SecureTx) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.db.Update(func(tx *bbolt.Tx) error {

		return fn(&SecureTx{
			tx:      tx,
			aead:    s.aead,    // Pass AEAD cipher
			keyLock: s.keyLock, // Pass keyLock
		})
	})
}

// DeleteBucket deletes the bucket with the given name.
func (stx *SecureTx) DeleteBucket(name []byte) error {
	return stx.tx.DeleteBucket(name)
}

func (stx *SecureTx) CreateBucket(name []byte) (*SecureBucket, error) {
	bucket, err := stx.tx.CreateBucket(name)
	if err != nil {
		return nil, err
	}
	return &SecureBucket{
		bucket:  bucket,
		aead:    stx.aead,    // Use AEAD from SecureTx
		keyLock: stx.keyLock, // Pass keyLock from SecureTx
	}, nil
}

func (stx *SecureTx) CreateBucketIfNotExists(name []byte) (*SecureBucket, error) {
	bucket, err := stx.tx.CreateBucketIfNotExists(name)
	if err != nil {
		return nil, err
	}
	return &SecureBucket{
		bucket:  bucket,
		aead:    stx.aead,    // Use AEAD from SecureTx
		keyLock: stx.keyLock, // Pass keyLock from SecureTx
	}, nil
}

func (stx *SecureTx) Bucket(name []byte) (*SecureBucket, error) {
	bucket := stx.tx.Bucket(name)
	if bucket == nil {
		return nil, fmt.Errorf("bucket %q not found", name)
	}
	return &SecureBucket{
		bucket:  bucket,
		aead:    stx.aead,
		keyLock: stx.keyLock, // Pass keyLock from SecureTx
	}, nil
}

type SecureBucket struct {
	bucket  *bbolt.Bucket
	aead    cipher.AEAD
	keyLock *memguard.LockedBuffer
}

// Put encrypts the value and stores it in the underlying bucket with the given key.
func (sb *SecureBucket) Put(key, value []byte) error {
	if len(key) == 0 {
		return errors.New("key cannot be empty")
	}
	if value == nil {
		value = []byte{}
	}

	encryptedValue, err := encryptData(value, sb.aead)
	if err != nil {
		return err
	}

	return sb.bucket.Put(key, encryptedValue)
}

// Get retrieves the encrypted value for a given key and decrypts it.
func (sb *SecureBucket) Get(key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, errors.New("key cannot be empty")
	}

	encryptedValue := sb.bucket.Get(key)
	if encryptedValue == nil {
		return nil, nil
	}

	value, err := decryptData(encryptedValue, sb.aead)
	if err != nil {
		return nil, err
	}

	return value, nil
}

// Delete removes the key and its value from the bucket.
func (sb *SecureBucket) Delete(key []byte) error {
	if len(key) == 0 {
		return errors.New("key cannot be empty")
	}
	return sb.bucket.Delete(key)
}

// ForEach calls the provided function with each key and decrypted value in the bucket.
func (sb *SecureBucket) ForEach(fn func(k, v []byte) error) error {
	return sb.bucket.ForEach(func(k, encV []byte) error {
		value, err := decryptData(encV, sb.aead)
		if err != nil {
			return err
		}
		return fn(k, value)
	})
}

// Cursor creates a new cursor associated with the bucket.
func (sb *SecureBucket) Cursor() *SecureCursor {
	return &SecureCursor{
		cursor:  sb.bucket.Cursor(),
		aead:    sb.aead,    // Add this line to initialize aead
		keyLock: sb.keyLock, // Pass keyLock
	}
}

type SecureCursor struct {
	cursor  *bbolt.Cursor
	aead    cipher.AEAD
	keyLock *memguard.LockedBuffer
}

// First moves the cursor to the first key/value pair and returns it.
func (sc *SecureCursor) First() ([]byte, []byte, error) {
	k, encV := sc.cursor.First()
	if k == nil || encV == nil {
		return k, nil, nil
	}
	v, err := decryptData(encV, sc.aead)
	if err != nil {
		return k, nil, fmt.Errorf("failed to decrypt value for key %q: %w", k, err)
	}
	return k, v, nil
}

// Next moves the cursor to the next key/value pair and returns it.
func (sc *SecureCursor) Next() ([]byte, []byte, error) {
	k, encV := sc.cursor.Next()
	if k == nil || encV == nil {
		return k, nil, nil // No more entries
	}
	v, err := decryptData(encV, sc.aead)
	if err != nil {
		return k, nil, fmt.Errorf("failed to decrypt value for key %q: %w", k, err)
	}
	return k, v, nil
}

// Prev moves the cursor to the previous key/value pair and returns it.
func (sc *SecureCursor) Prev() ([]byte, []byte, error) {
	k, encV := sc.cursor.Prev()
	if k == nil || encV == nil {
		return k, nil, nil // No more entries
	}
	v, err := decryptData(encV, sc.aead)
	if err != nil {
		return k, nil, fmt.Errorf("failed to decrypt value for key %q: %w", k, err)
	}
	return k, v, nil
}

// Seek moves the cursor to a given key and returns the associated key/value pair.
func (sc *SecureCursor) Seek(seek []byte) ([]byte, []byte, error) {
	k, encV := sc.cursor.Seek(seek)
	if k == nil || encV == nil {
		return k, nil, nil // No matching entry
	}
	v, err := decryptData(encV, sc.aead)
	if err != nil {
		return k, nil, fmt.Errorf("failed to decrypt value for key %q: %w", k, err)
	}
	return k, v, nil
}

func encryptData(data []byte, aead cipher.AEAD) ([]byte, error) {

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	ciphertext := aead.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// decryptData decrypts the data using AES-GCM.
func decryptData(encryptedData []byte, aead cipher.AEAD) ([]byte, error) {

	if encryptedData == nil {
		return nil, nil
	}
	if len(encryptedData) < aead.NonceSize() {
		return nil, errors.New("encrypted data is too short")
	}
	nonce, ciphertext := encryptedData[:aead.NonceSize()], encryptedData[aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}
	return plaintext, nil
}
