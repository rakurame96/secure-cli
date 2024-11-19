use aes_gcm::aead::{Aead, KeyInit}; // Traits for encryption
use aes_gcm::{AeadCore, Aes256Gcm, Key, Nonce}; // AES-GCM encryption
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher};
use chacha20poly1305::ChaCha20Poly1305; // ChaCha20-Poly1305 encryption
use clap::{Arg, ArgAction, Command};
use rand::rngs::OsRng; // For secure random salt generation
use rpassword::prompt_password;
use std::fs;

enum EncryptionAlgorithm {
    AES256GCM,
    ChaCha20Poly1305,
}

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

fn main() -> Result<(), Box<dyn std::error::Error>> {
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
            println!("Showing metadata for file: {}", input);
        }
        _ => {
            eprintln!("Please specify a valid command (encrypt, decrypt, show).");
        }
    }

    Ok(())
}

fn encrypt_file(
    input_path: &str,
    output_path: &str,
    key: &[u8],
    salt: &str,
    algorithm: &EncryptionAlgorithm,
) -> Result<(), Box<dyn std::error::Error>> {
    let plaintext = fs::read(input_path)?;
    println!(
        "Read plaintext from {}: {:?}",
        input_path,
        &plaintext[..std::cmp::min(20, plaintext.len())]
    ); // Print first 20 bytes
    let nonce = match algorithm {
        EncryptionAlgorithm::AES256GCM => Aes256Gcm::generate_nonce(&mut OsRng),
        EncryptionAlgorithm::ChaCha20Poly1305 => {
            chacha20poly1305::ChaCha20Poly1305::generate_nonce(&mut OsRng)
        }
    };
    println!("Generated nonce: {:?}", nonce);
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
    println!(
        "Encrypted ciphertext: {:?}",
        &ciphertext[..std::cmp::min(20, ciphertext.len())]
    ); // Print first 20 bytes

    let mut output_data = Vec::new();
    output_data.extend_from_slice(&nonce);
    output_data.extend_from_slice(salt.trim_end_matches('=').as_bytes());
    output_data.extend_from_slice(&ciphertext);
    println!("Final output data length: {}", output_data.len());

    fs::write(output_path, output_data)?;
    println!("Data written to file: {}", output_path);

    Ok(())
}

fn decrypt_file(
    input_path: &str,
    output_path: &str,
    passphrase: &str,
    algorithm: &EncryptionAlgorithm,
) -> Result<(), Box<dyn std::error::Error>> {
    let salt_len: usize = 22; // Length of base64 encoded salt without padding
    println!("Decrypting file: {}", input_path);

    let encrypted_data = fs::read(input_path)?;
    println!(
        "Read encrypted data from {}: {:?}",
        input_path,
        &encrypted_data[..std::cmp::min(20, encrypted_data.len())]
    ); // Print first 20 bytes

    let (nonce, rest) = encrypted_data.split_at(12); // 96-bit nonce
    println!("Extracted nonce: {:?}", nonce);

    let (salt, ciphertext) = rest.split_at(salt_len);
    println!(
        "Extracted salt: {:?} and ciphertext length: {}",
        salt,
        ciphertext.len()
    );

    let salt_str = std::str::from_utf8(salt)?;
    println!("Salt string: {}", salt_str);

    let key = derive_key(passphrase, salt_str)?;
    println!("Derived key: {:?}", key);

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
    println!(
        "Decrypted plaintext: {:?}",
        &plaintext[..std::cmp::min(20, plaintext.len())]
    ); // Print first 20 bytes

    fs::write(output_path, &plaintext)?;
    println!("Decrypted data written to file: {}", output_path);

    Ok(())
}
