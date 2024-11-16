# secure-cli
Secure File Encryption/Decryption CLI

# problem statement can be found here: [Link](https://docs.google.com/document/d/1_mULXR9q8rWzeSYD2MjIqcgM0BcuGiJHRfBKzndBJoQ/edit?tab=t.0#heading=h.84ttm8z7nxay)

# Description
**Project Description:** Secure File Encryption/Decryption CLI

**Goal:** Build a simple command-line tool that lets you securely lock (encrypt) and unlock (decrypt) files using a secret key. It keeps file data safe, even during unexpected crashes or power loss.

**What It Does:**
1. Encrypt/Decrypt Files:
  - Protect the contents of a file and its name.
  - Keep the original filename private so the encrypted file doesn’t reveal how long the filename is.
2. Crash Protection:
  - Ensure that files won’t get corrupted if the process stops unexpectedly. This technique uses reliable Write-Ahead Logging (WAL).
3. Show File Info:
  - It lets users see details about the encrypted file (such as its name, size, and encryption method) without decrypting it.

**How It Works:**
1. Encryption Algorithms:
  - Choose between two secure methods:
  - AES-GCM (a type of AES encryption)
  - ChaCha20-Poly1305 (another widely used encryption method).
  - Both are solid options for keeping files safe.
2. CLI Commands:
  - encrypt: Lock a file (turn it into an unreadable, encrypted version).
  - decrypt: Unlock a file (restore it to its original readable form).
  - show: View information about an encrypted file without unlocking it.
3. Command Options:
  - Choose the algorithm: Use—-alg (or—a) to select an encryption method, such as AES-GCM-128, AES-GCM-196, AES-GCM-256, or ChaCha20Poly1305.
  - Input and output files:
  - Specify the file to process with --in (or -i).
  - Optionally, use --out (or -o) to define where the result should go. If skipped, the input file is replaced directly.
4. Secure Passphrase:
  - When it starts, the tool will ask you for a passphrase (like a password).
  - The passphrase isn’t stored anywhere, and it’s converted into a strong key to lock/unlock the file.

Bonus Features:
1. Support for "age" Format:
  - Use the "age" encryption format, a modern and user-friendly way to secure files. (Optional, can be added using the rage library).
2. Support for OpenPGP:
  - Add compatibility with OpenPGP, a popular encryption standard used for email and files. (Optional, can be added using the rpgp library).


For these you’ll generate a random key and encrypt it with age or OpenPGP to sent to user2 and pass that key as param to cli. You’ll then send the key and encrypted file to user2 who will pass them to the app to decrypt.

**How to Submit:**
1. Create a public GitHub repository with your project code.
2. Share the repository link via email to radumarias@gmail.com.
3. Deadline: 25th November 19:00 GMT+2

**Implementation**
*Crates you could use*
* https://crates.io/crates/ring
* https://crates.io/crates/chacha20poly1305
* https://crates.io/crates/aes-gcm
* https://crates.io/crates/rand
* https://crates.io/crates/rand_chacha
* https://crates.io/crates/argon2
* https://crates.io/crates/blake3
* https://crates.io/crates/clap
* https://crates.io/crates/thiserror
* https://crates.io/crates/tracing
* https://crates.io/crates/rpassword
* https://crates.io/crates/ctrlc
* https://crates.io/crates/okaywal
* https://crates.io/crates/shush-rs
