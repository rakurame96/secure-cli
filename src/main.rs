use aes_gcm::aead::{Aead, KeyInit}; // Traits for encryption
use aes_gcm::{AeadCore, Aes256Gcm, Key, Nonce}; // AES-GCM encryption
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher};
use chacha20poly1305::ChaCha20Poly1305; // ChaCha20-Poly1305 encryption
use clap::{Arg, ArgAction, Command};
use rand::rngs::OsRng; // For secure random salt generation
use rpassword::prompt_password;
use serde::{Deserialize, Serialize};
use std::fs;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::Path;

/// Metadata structure for encrypted files
#[derive(Serialize, Deserialize, Debug)]
struct Metadata {
    /// Original filename
    filename: String,
    /// File size in bytes
    size: usize,
    /// Encryption algorithm used
    algorithm: String,
}

/// Write-Ahead Logging (WAL) entry structure
#[derive(Serialize, Deserialize, Debug)]
struct WalEntry {
    /// Operation type (e.g., encrypt, decrypt)
    operation: String,
    /// Input file path
    input_path: String,
    /// Output file path
    output_path: String,
    /// Salt used for key derivation
    salt: String,
    /// Encryption algorithm used
    algorithm: String,
}

/// Supported encryption algorithms
enum EncryptionAlgorithm {
    /// AES256GCM encryption algorithm
    AES256GCM,
    /// ChaCha20Poly1305 encryption algorithm
    ChaCha20Poly1305,
}

/// Derives a 256-bit key from a passphrase and salt using Argon2
///
/// # Arguments
///
/// * `passphrase` - The passphrase to derive the key from
/// * `salt` - The salt to use for key derivation
///
/// # Returns
///
/// A 256-bit key as an array of 32 bytes
fn derive_key(passphrase: &str, salt: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    println!(
        "Deriving key with passphrase: {} and salt: {}",
        passphrase, salt
    );
    let salt = SaltString::from_b64(salt.trim_end_matches('=')).map_err(|e| {
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            e.to_string(),
        ))
    })?;

    let argon2 = Argon2::default();

    let hash = argon2
        .hash_password(passphrase.as_bytes(), &salt)
        .map_err(|e| {
            Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))
        })?;

    let hash_bytes = hash.hash.ok_or_else(|| {
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Failed to retrieve hash bytes",
        ))
    })?;

    let mut key = [0u8; 32];
    key.copy_from_slice(&hash_bytes.as_bytes()[..32]);

    println!("Derived key: {:?}", key);
    Ok(key)
}


/// Entry point of the Secure CLI Tool.
///
/// This function sets up the command-line interface, processes commands,
/// and invokes the appropriate functions for encryption, decryption, and metadata display.
/// It also performs recovery from Write-Ahead Logging (WAL) to ensure data integrity.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    recover_from_wal()?;

    let matches = Command::new("Secure CLI")
        .version("0.1.0")
        .about("File Encryption and Decryption Tool")
        .subcommand(
            Command::new("encrypt")
                .about("Encrypt a file")
                .arg(
                    Arg::new("input")
                        .long("input")
                        .short('i')
                        .required(true)
                        .value_name("INPUT")
                        .help("Input file path")
                        .action(ArgAction::Set),
                )
                .arg(
                    Arg::new("output")
                        .long("output")
                        .short('o')
                        .value_name("OUTPUT")
                        .help("Output file path (optional)")
                        .action(ArgAction::Set),
                )
                .arg(
                    Arg::new("algorithm")
                        .long("algorithm")
                        .short('a')
                        .value_name("ALGORITHM")
                        .help("Encryption algorithm to use (AES256GCM or ChaCha20Poly1305)")
                        .action(ArgAction::Set)
                        .default_value("AES256GCM"),
                ),
        )
        .subcommand(
            Command::new("decrypt")
                .about("Decrypt a file")
                .arg(
                    Arg::new("input")
                        .long("input")
                        .short('i')
                        .required(true)
                        .value_name("INPUT")
                        .help("Input file path")
                        .action(ArgAction::Set),
                )
                .arg(
                    Arg::new("output")
                        .long("output")
                        .short('o')
                        .value_name("OUTPUT")
                        .help("Output file path (optional)")
                        .action(ArgAction::Set),
                )
                .arg(
                    Arg::new("algorithm")
                        .long("algorithm")
                        .short('a')
                        .value_name("ALGORITHM")
                        .help("Encryption algorithm to use (AES256GCM or ChaCha20Poly1305)")
                        .action(ArgAction::Set)
                        .default_value("AES256GCM"),
                ),
        )
        .subcommand(
            Command::new("show")
                .about("Show metadata of an encrypted file")
                .arg(
                    Arg::new("input")
                        .long("input")
                        .short('i')
                        .required(true)
                        .value_name("INPUT")
                        .help("Encrypted file path")
                        .action(ArgAction::Set),
                ),
        )
        .get_matches();

    match matches.subcommand() {
        Some(("encrypt", sub_matches)) => {
            let algorithm = match sub_matches
                .get_one::<String>("algorithm")
                .map(|s| s.as_str())
            {
                Some("AES256GCM") => EncryptionAlgorithm::AES256GCM,
                Some("ChaCha20Poly1305") => EncryptionAlgorithm::ChaCha20Poly1305,
                _ => {
                    eprintln!(
                        "Invalid algorithm. Please choose between AES256GCM or ChaCha20Poly1305."
                    );
                    return Ok(());
                }
            };

            let input = sub_matches.get_one::<String>("input").unwrap();
            println!("Encrypting file: {}", input);
            let output = sub_matches
                .get_one::<String>("output")
                .map(|s| s.to_owned())
                .unwrap_or_else(|| format!("{}.enc", input));
            println!("Output file: {}", output);
            let passphrase = prompt_password("Enter passphrase: ").unwrap();
            let salt = SaltString::generate(&mut OsRng).to_string();
            println!("Generated salt: {}", salt);
            let key = derive_key(&passphrase, &salt)?;

            match encrypt_file(input, &output, &key, &salt, &algorithm) {
                Ok(_) => println!("File encrypted successfully: {}", output),
                Err(e) => eprintln!("Error encrypting file: {}", e),
            }
        }
        Some(("decrypt", sub_matches)) => {
            let algorithm = match sub_matches
                .get_one::<String>("algorithm")
                .map(|s| s.as_str())
            {
                Some("AES256GCM") => EncryptionAlgorithm::AES256GCM,
                Some("ChaCha20Poly1305") => EncryptionAlgorithm::ChaCha20Poly1305,
                _ => {
                    eprintln!(
                        "Invalid algorithm. Please choose between AES256GCM or ChaCha20Poly1305."
                    );
                    return Ok(());
                }
            };

            let input = sub_matches.get_one::<String>("input").unwrap();
            println!("Decrypting file: {}", input);
            let output = sub_matches
                .get_one::<String>("output")
                .map(|s| s.to_owned())
                .unwrap_or_else(|| format!("{}.dec", input));
            println!("Output file: {}", output);
            let passphrase = prompt_password("Enter passphrase: ").unwrap();

            match decrypt_file(input, &output, &passphrase, &algorithm) {
                Ok(_) => println!("File decrypted successfully: {}", output),
                Err(e) => eprintln!("Error decrypting file: {}", e),
            }
        }
        Some(("show", sub_matches)) => {
            let input = sub_matches.get_one::<String>("input").unwrap();
            match show_metadata(input) {
                Ok(_) => println!("Metadata displayed successfully."),
                Err(e) => eprintln!("Error displaying metadata: {}", e),
            }
        }
        _ => {
            eprintln!("Please specify a valid command (encrypt, decrypt, show).");
        }
    }

    Ok(())
}

/// Shows the metadata of an encrypted file.
///
/// This function reads the encrypted file, extracts the metadata, and displays it
/// without decrypting the file contents.
///
/// # Arguments
///
/// * `input_path` - A string slice that holds the path of the encrypted file
///
/// # Returns
///
/// This function returns a `Result` indicating success or failure.
fn show_metadata(input_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let encrypted_data = fs::read(input_path)?;
    let (_, rest) = encrypted_data.split_at(12 + 22); // Skip nonce and salt
    let metadata_end = rest
        .iter()
        .position(|&b| b == 0)
        .ok_or("Metadata not found")?;
    let metadata_json = &rest[..metadata_end];

    let metadata: Metadata = serde_json::from_slice(metadata_json)?;
    println!("Metadata for {}: {:?}", input_path, metadata);

    Ok(())
}

/// Writes a WAL entry to the WAL file
///
/// # Arguments
///
/// * `entry` - The WAL entry to write
///
/// # Returns
///
/// Result indicating success or failure
fn write_wal_entry(entry: &WalEntry) -> Result<(), Box<dyn std::error::Error>> {
    let wal_path = "secure_cli.wal";
    let mut wal = OpenOptions::new()
        .append(true)
        .create(true)
        .open(wal_path)?;

    wal.write_all(&serde_json::to_vec(&entry)?)?;
    wal.write_all(b"\n")?;
    wal.flush()?;
    println!("WAL entry written: {:?}", entry);

    Ok(())
}

/// Recovers from Write-Ahead Logging (WAL).
///
/// This function reads the WAL file to identify incomplete operations due to a crash or failure.
/// It then handles these operations based on their type (encryption or decryption).
///
/// # Returns
///
/// This function returns a `Result` indicating success or failure.
fn recover_from_wal() -> Result<(), Box<dyn std::error::Error>> {
    let wal_path = "secure_cli.wal";

    if !std::path::Path::new(wal_path).exists() {
        return Ok(());
    }

    let mut wal = OpenOptions::new().read(true).open(wal_path)?;
    let mut wal_data = String::new();
    wal.read_to_string(&mut wal_data)?;

    let entries: Vec<WalEntry> = wal_data
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();

    for entry in entries {
        println!("Recovering operation: {:?}", entry);
        // Handle recovery logic based on operation type
        // For this example, we'll just print the operation
    }

    // Clean up the WAL after recovery
    std::fs::remove_file(wal_path)?;
    println!("WAL entry cleaned up after recovery");

    Ok(())
}

/// Encrypts a file using the specified encryption algorithm
///
/// # Arguments
///
/// * `input_path` - Path to the input file
/// * `output_path` - Path to the output encrypted file
/// * `key` - Encryption key
/// * `salt` - Salt used for key derivation
/// * `algorithm` - Encryption algorithm to use
///
/// # Returns
///
/// Result indicating success or failure
fn encrypt_file(
    input_path: &str,
    output_path: &str,
    key: &[u8],
    salt: &str,
    algorithm: &EncryptionAlgorithm,
) -> Result<(), Box<dyn std::error::Error>> {
    let wal_entry = WalEntry {
        operation: "encrypt".to_string(),
        input_path: input_path.to_string(),
        output_path: output_path.to_string(),
        salt: salt.to_string(),
        algorithm: match algorithm {
            EncryptionAlgorithm::AES256GCM => "AES256GCM",
            EncryptionAlgorithm::ChaCha20Poly1305 => "ChaCha20Poly1305",
        }
        .to_string(),
    };

    write_wal_entry(&wal_entry)?;

    let plaintext = fs::read(input_path)?;
    let nonce = match algorithm {
        EncryptionAlgorithm::AES256GCM => Aes256Gcm::generate_nonce(&mut OsRng),
        EncryptionAlgorithm::ChaCha20Poly1305 => {
            chacha20poly1305::ChaCha20Poly1305::generate_nonce(&mut OsRng)
        }
    };
    let ciphertext = match algorithm {
        EncryptionAlgorithm::AES256GCM => {
            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
            cipher
                .encrypt(&nonce, plaintext.as_ref())
                .map_err(|_| "Encryption failed")?
        }
        EncryptionAlgorithm::ChaCha20Poly1305 => {
            let cipher = chacha20poly1305::ChaCha20Poly1305::new(Key::<
                chacha20poly1305::ChaCha20Poly1305,
            >::from_slice(key));
            cipher
                .encrypt(&nonce, plaintext.as_ref())
                .map_err(|_| "Encryption failed")?
        }
    };

    let metadata = Metadata {
        filename: String::from(input_path),
        size: plaintext.len(),
        algorithm: match algorithm {
            EncryptionAlgorithm::AES256GCM => "AES256GCM",
            EncryptionAlgorithm::ChaCha20Poly1305 => "ChaCha20Poly1305",
        }
        .to_string(),
    };

    let metadata_json = serde_json::to_string(&metadata)?;
    let mut output_data = Vec::new();
    output_data.extend_from_slice(&nonce);
    output_data.extend_from_slice(salt.trim_end_matches('=').as_bytes());
    output_data.extend_from_slice(metadata_json.as_bytes());
    output_data.push(0); // Null separator between metadata and ciphertext
    output_data.extend_from_slice(&ciphertext);

    fs::write(output_path, output_data)?;

    // Clean up WAL entry after successful operation
    std::fs::remove_file("secure_cli.wal")?;
    println!("WAL entry cleaned up");

    Ok(())
}

/// Decrypts a file using the specified encryption algorithm
///
/// # Arguments
///
/// * `input_path` - Path to the input encrypted file
/// * `output_path` - Path to the output decrypted file
/// * `passphrase` - Passphrase used for key derivation
/// * `algorithm` - Encryption algorithm used for encryption
///
/// # Returns
///
/// Result indicating success or failure
fn decrypt_file(
    input_path: &str,
    output_path: &str,
    passphrase: &str,
    algorithm: &EncryptionAlgorithm,
) -> Result<(), Box<dyn std::error::Error>> {
    let wal_entry = WalEntry {
        operation: "decrypt".to_string(),
        input_path: input_path.to_string(),
        output_path: output_path.to_string(),
        salt: String::new(), // Salt will be extracted from the file
        algorithm: match algorithm {
            EncryptionAlgorithm::AES256GCM => "AES256GCM",
            EncryptionAlgorithm::ChaCha20Poly1305 => "ChaCha20Poly1305",
        }
        .to_string(),
    };

    write_wal_entry(&wal_entry)?;

    let salt_len: usize = 22; // Length of base64 encoded salt without padding
    let encrypted_data = fs::read(input_path)?;
    let (nonce, rest) = encrypted_data.split_at(12); // 96-bit nonce
    let (salt, rest) = rest.split_at(salt_len);
    let metadata_end = rest
        .iter()
        .position(|&b| b == 0)
        .ok_or("Metadata not found")?;
    let metadata_json = &rest[..metadata_end];
    let ciphertext = &rest[(metadata_end + 1)..]; // Skip null separator

    let salt_str = std::str::from_utf8(salt)?;
    let key = derive_key(passphrase, salt_str)?;

    let plaintext = match algorithm {
        EncryptionAlgorithm::AES256GCM => {
            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
            cipher
                .decrypt(Nonce::from_slice(nonce), ciphertext)
                .map_err(|_| "Decryption failed")?
        }
        EncryptionAlgorithm::ChaCha20Poly1305 => {
            let cipher = chacha20poly1305::ChaCha20Poly1305::new(Key::<
                chacha20poly1305::ChaCha20Poly1305,
            >::from_slice(&key));
            cipher
                .decrypt(Nonce::from_slice(nonce), ciphertext)
                .map_err(|_| "Decryption failed")?
        }
    };

    fs::write(output_path, &plaintext)?;

    // Clean up WAL entry after successful operation
    std::fs::remove_file("secure_cli.wal")?;
    println!("WAL entry cleaned up");

    Ok(())
}
