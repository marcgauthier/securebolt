
```markdown
# SecureBolt

SecureBolt is a Go package that provides transparent, secure encryption for your data stored in [BoltDB (bbolt)](https://github.com/etcd-io/bbolt), an embedded key-value database. It leverages strong cryptographic practices to ensure data confidentiality and integrity, making it suitable for applications that require secure data storage without the overhead of managing external databases.

## Features

- **Transparent Encryption**: Data is automatically encrypted before storage and decrypted upon retrieval.
- **Strong Cryptography**: Uses AES-GCM for encryption and Argon2id for key derivation.
- **Secure Memory Handling**: Employs [memguard](https://github.com/awnumar/memguard) to protect sensitive data in memory.
- **BoltDB Compatibility**: Provides an API similar to BoltDB for easy integration.
- **Thread Safety**: Designed with concurrency in mind using mutexes for safe access.

## Installation

To install SecureBolt, run:

```bash
go get github.com/yourusername/securebolt
```

Replace `github.com/marcgauthier/securebolt` with the actual import path of the package.

## Usage

### Opening a Secure Database

To start using SecureBolt, you need to open or create a database by providing a filename, file mode, and a password. The password is used to derive the encryption key securely.

```go
package main

import (
    "log"
    "github.com/yourusername/securebolt"
    "github.com/awnumar/memguard"
)

func main() {
    // Ensure memguard catches interrupts to securely destroy sensitive data
    memguard.CatchInterrupt()

    // Use a strong, high-entropy password
    password := []byte("your-secure-password")

    // Open or create the database
    db, err := securebolt.Open("mydb.db", 0600, password)
    if err != nil {
        log.Fatal(err)
    }
    defer func() {
        // Close the database securely
        if err := db.Close(); err != nil {
            log.Fatal(err)
        }
    }()

    // Securely wipe the password from memory
    memguard.WipeBytes(password)

    // Your application logic here...
}
```

### Storing Data

```go
err = db.Update(func(tx *securebolt.SecureTx) error {
    // Create or retrieve a bucket
    bucket, err := tx.CreateBucketIfNotExists([]byte("MyBucket"))
    if err != nil {
        return err
    }

    // Store a key-value pair (both key and value are byte slices)
    key := []byte("username")
    value := []byte("john_doe")
    return bucket.Put(key, value)
})
if err != nil {
    log.Fatal(err)
}
```

### Retrieving Data

```go
err = db.View(func(tx *securebolt.SecureTx) error {
    // Retrieve the bucket
    bucket, err := tx.Bucket([]byte("MyBucket"))
    if err != nil {
        return err
    }

    // Retrieve the value for a key
    key := []byte("username")
    value, err := bucket.Get(key)
    if err != nil {
        return err
    }

    if value == nil {
        log.Println("Key not found")
    } else {
        log.Printf("Retrieved value: %s\n", value)
    }
    return nil
})
if err != nil {
    log.Fatal(err)
}
```

### Deleting Data

```go
err = db.Update(func(tx *securebolt.SecureTx) error {
    bucket, err := tx.Bucket([]byte("MyBucket"))
    if err != nil {
        return err
    }

    // Delete the key-value pair
    key := []byte("username")
    return bucket.Delete(key)
})
if err != nil {
    log.Fatal(err)
}
```

### Iterating Over Data

```go
err = db.View(func(tx *securebolt.SecureTx) error {
    bucket, err := tx.Bucket([]byte("MyBucket"))
    if err != nil {
        return err
    }

    // Iterate over all key-value pairs in the bucket
    err = bucket.ForEach(func(k, v []byte) error {
        log.Printf("Key: %s, Value: %s\n", k, v)
        return nil
    })
    return err
})
if err != nil {
    log.Fatal(err)
}
```

### Using a Cursor

```go
err = db.View(func(tx *securebolt.SecureTx) error {
    bucket, err := tx.Bucket([]byte("MyBucket"))
    if err != nil {
        return err
    }

    cursor := bucket.Cursor()

    for k, v, err := cursor.First(); k != nil && err == nil; k, v, err = cursor.Next() {
        if err != nil {
            return err
        }
        log.Printf("Key: %s, Value: %s\n", k, v)
    }

    return nil
})
if err != nil {
    log.Fatal(err)
}
```

### Handling Transactions

SecureBolt supports read-only and read-write transactions similar to BoltDB.

- **Read-Only Transaction**: Use `db.View()` to create a read-only transaction.
- **Read-Write Transaction**: Use `db.Update()` to create a read-write transaction.

## Security Considerations

- **Password Management**: Use a strong, high-entropy password and securely erase it from memory after use with `memguard.WipeBytes()`.

- **Key Derivation**: SecureBolt uses Argon2id with sensible defaults for time, memory, and parallelism. Adjust these parameters in `deriveKey()` if needed.

- **Salt Storage**: The salt used for key derivation is stored unencrypted in the database's `securebolt_meta` bucket. Do not modify or expose this bucket.

- **Memory Protection**: Sensitive data is stored in locked buffers to prevent memory paging and unauthorized access.

- **Encryption Details**: Data is encrypted using AES-GCM, which provides both confidentiality and integrity. Do not change the encryption algorithm unless necessary and you understand the implications.

## Limitations

- **Single Password**: The entire database uses a single password. There's no support for multiple passwords or user-specific encryption keys.

- **No Key Rotation**: Changing the encryption password requires creating a new database and migrating data.

- **Concurrency**: While SecureBolt uses mutexes for thread safety, high levels of concurrency may affect performance.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request on GitHub.

## Acknowledgments

- [BoltDB (bbolt)](https://github.com/etcd-io/bbolt) for the underlying key-value database.
- [memguard](https://github.com/awnumar/memguard) for secure memory handling.
- [Argon2](https://github.com/P-H-C/phc-winner-argon2) for the key derivation function.

---
