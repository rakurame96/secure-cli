Given your tight deadline, here's an accelerated plan to complete the project by November 25. The focus will be on delivering a functional MVP (minimum viable product) with room for refinement later.

---

### **Day 1: Project Setup and CLI Skeleton**
- **Goal**: Get the project structure and CLI commands ready.
- **Tasks**:
  1. Initialize the project (`cargo new secure-cli`) and add dependencies.
  2. Implement basic CLI commands (`encrypt`, `decrypt`, `show`) using `clap`.
  3. Test commands to ensure proper argument parsing.

---

### **Day 2: Core Encryption and Decryption Logic**
- **Goal**: Implement basic file encryption and decryption.
- **Tasks**:
  1. Write the `encrypt_file` and `decrypt_file` functions using `aes-gcm` or `chacha20poly1305`.
  2. Integrate these functions with CLI commands.
  3. Test with small sample files.

**ToDo**
- Once these functions are working correctly:
  - Update the key generation mechanism to use a secure passphrase.
  - Handle larger files (streaming encryption/decryption).
  - Add more encryption algorithms (e.g., ChaCha20-Poly1305).

---

### **Day 3: Passphrase Handling and Key Derivation**
- **Goal**: Securely derive encryption keys from user-provided passphrases.
- **Tasks**:
  1. Use `rpassword` for passphrase input.
  2. Use `argon2` to derive a key from the passphrase and a fixed salt (for simplicity now).
  3. Ensure the key derivation integrates seamlessly with `encrypt_file` and `decrypt_file`.

---

### **Day 4: Metadata and Show Command**
- **Goal**: Add metadata handling for encrypted files.
- **Tasks**:
  1. Define a metadata structure (e.g., filename, size, encryption algorithm).
  2. Store metadata alongside the encrypted content.
  3. Implement the `show` command to display metadata without decryption.

---

### **Day 5: Crash Protection**
- **Goal**: Add Write-Ahead Logging (WAL) for resilience.
- **Tasks**:
  1. Use `okaywal` or write a basic `.wal` file to track operations.
  2. Ensure `.wal` entries are cleaned up after successful operations.

---

### **Day 6: Final Testing and Polishing**
- **Goal**: Ensure everything works as expected.
- **Tasks**:
  1. Test all features (`encrypt`, `decrypt`, `show`) with edge cases.
  2. Write a `README.md` with usage instructions.
  3. Package and prepare the project for sharing (e.g., GitHub).

---

### **Day 7: Buffer for Unforeseen Issues**
- Use this day to fix bugs, address edge cases, or add small refinements.

---

### Key Time-Saving Tips:
1. **Focus on Essentials**:
   - Defer optional features like support for the "age" format or OpenPGP.
2. **Reuse Libraries**:
   - Use crates like `ring` or `okaywal` to avoid reinventing functionality.
3. **Simplify for Now**:
   - Use a fixed salt for key derivation or predefined algorithms (AES-GCM-256).

---

Let me know how you'd like to proceed or if you want detailed support for any step!

# Test encryption command (default AES256GCM)
cargo run -- encrypt --input file.txt --output file.enc

# Test decryption command (default AES256GCM)
cargo run -- decrypt --input file.enc --output file.txt

# Test with different algorithm for Encryption (ChaCha20Poly1305)
cargo run -- encrypt --input file.txt --output file.enc --algorithm ChaCha20Poly1305

# Test with different algorithm for Encryption (ChaCha20Poly1305)
cargo run -- decrypt --input file.enc --output file.txt --algorithm ChaCha20Poly1305

# Test show command
cargo run -- show --input file.enc

# Show metadata for an encrypted file 
cargo run -- show --input encrypted_file.enc


### Final Testing
# Step 1: Test All Features with Edge Cases
Let's test the encrypt, decrypt, and show features with various edge cases to ensure they work as expected.

**Test Case 1: Encrypt and Decrypt a Small File**
```sh
echo "This is a small file." > smallfile.txt
cargo run -- encrypt --input smallfile.txt --output smallfile.enc
cargo run -- show --input smallfile.enc
cargo run -- decrypt --input smallfile.enc --output smallfile_dec.txt
diff smallfile.txt smallfile_dec.txt
```

**Test Case 2: Encrypt and Decrypt a Large File**
```sh
dd if=/dev/zero of=largefile.txt bs=1M count=1024
cargo run -- encrypt --input largefile.txt --output largefile.enc
cargo run -- show --input largefile.enc
cargo run -- decrypt --input largefile.enc --output largefile_dec.txt
diff largefile.txt largefile_dec.txt
```

**Test Case 3: Encrypt and Decrypt with Different Algorithms**
```sh
echo "Testing with AES256GCM algorithm" > testfile.txt
cargo run -- encrypt --input testfile.txt --output testfile_aes.enc --algorithm AES256GCM
cargo run -- show --input testfile_aes.enc
cargo run -- decrypt --input testfile_aes.enc --output testfile_aes_dec.txt
diff testfile.txt testfile_aes_dec.txt

echo "Testing with ChaCha20Poly1305 algorithm" > testfile.txt
cargo run -- encrypt --input testfile.txt --output testfile_chacha.enc --algorithm ChaCha20Poly1305
cargo run -- show --input testfile_chacha.enc
cargo run -- decrypt --input testfile_chacha.enc --output testfile_chacha_dec.txt
diff testfile.txt testfile_chacha_dec.txt
```