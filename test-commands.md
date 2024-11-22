### Test encryption command (default AES256GCM)
cargo run -- encrypt --input file.txt --output file.enc

### Test decryption command (default AES256GCM)
cargo run -- decrypt --input file.enc --output file.txt

### Test with different algorithm for Encryption (ChaCha20Poly1305)
cargo run -- encrypt --input file.txt --output file.enc --algorithm ChaCha20Poly1305

### Test with different algorithm for Encryption (ChaCha20Poly1305)
cargo run -- decrypt --input file.enc --output file.txt --algorithm ChaCha20Poly1305

### Test show command
cargo run -- show --input file.enc

### Show metadata for an encrypted file 
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