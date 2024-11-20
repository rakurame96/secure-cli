# Secure CLI Tool

## Overview

Secure CLI Tool is a command-line application for encrypting, decrypting, and displaying metadata of files using AES256GCM and ChaCha20Poly1305 encryption algorithms. It also includes Write-Ahead Logging (WAL) for resilience against crashes.

## Features

- Encrypt files
- Decrypt files
- Show metadata of encrypted files
- Write-Ahead Logging (WAL) for crash recovery

## Installation

Clone the repository and build the project using Cargo:

```sh
git clone <repository_url>
cd secure-cli
cargo build
```

## Usage

**Encrypt a File**

```sh
cargo run -- encrypt --input <INPUT_FILE> --output <OUTPUT_FILE> [--algorithm <ALGORITHM>]
```
- `<INPUT_FILE>`: Path to the input file to encrypt
- `<OUTPUT_FILE>`: Path to the output encrypted file
- `<ALGORITHM>`: Encryption algorithm to use (`AES256GCM` or `ChaCha20Poly1305`). Default is `AES256GCM`.

**Decrypt a File**
```sh
cargo run -- decrypt --input <INPUT_FILE> --output <OUTPUT_FILE> [--algorithm <ALGORITHM>]
```
- `<INPUT_FILE>`: Path to the input encrypted file
- `<OUTPUT_FILE>`: Path to the output decrypted file
- `<ALGORITHM>`: Encryption algorithm used for encryption (`AES256GCM` or `ChaCha20Poly1305`). Default is `AES256GCM`.

**Show Metadata of an Encrypted File**
```sh
cargo run -- show --input <INPUT_FILE>
```
- `<INPUT_FILE>`: Path to the encrypted file

## Contributing

Contributions are welcome! Please submit a pull request or open an issue to discuss your changes.

## License

This project is licensed under the MIT License.