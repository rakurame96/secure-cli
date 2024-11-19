use aes_gcm::aead::{Aead, KeyInit}; // Traits for encryption
use aes_gcm::{AeadCore, Aes256Gcm, Key, Nonce}; // AES-GCM encryption
use clap::{Arg, ArgAction, Command};
use std::fs;
// use std::path::Path;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher};
use rand::rngs::OsRng; // For secure random salt generation
use rpassword::prompt_password;

fn derive_key(passphrase: &str, salt: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
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
            let input = sub_matches.get_one::<String>("input").unwrap();
            let output = sub_matches
                .get_one::<String>("output")
                .map(|s| s.to_owned())
                .unwrap_or_else(|| format!("{}.enc", input));
            let passphrase = prompt_password("Enter passphrase: ").unwrap();
            let salt = SaltString::generate(&mut OsRng).to_string();
            let key = derive_key(&passphrase, &salt)?;

            match encrypt_file(input, &output, &key, &salt) {
                Ok(_) => println!("File encrypted successfully: {}", output),
                Err(e) => eprintln!("Error encrypting file: {}", e),
            }
        }
        Some(("decrypt", sub_matches)) => {
            let input = sub_matches.get_one::<String>("input").unwrap();
            let output = sub_matches
                .get_one::<String>("output")
                .map(|s| s.to_owned())
                .unwrap_or_else(|| format!("{}.dec", input));
            let passphrase = prompt_password("Enter passphrase: ").unwrap();

            match decrypt_file(input, &output, &passphrase) {
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
) -> Result<(), Box<dyn std::error::Error>> {
    let plaintext = fs::read(input_path)?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bit unique nonce
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_ref())
        .map_err(|_| "Encryption failed")?;

    let mut output_data = Vec::new();
    output_data.extend_from_slice(&nonce); // Store nonce at the beginning
    output_data.extend_from_slice(salt.trim_end_matches('=').as_bytes()); // Store salt without padding
    output_data.extend_from_slice(&ciphertext);

    fs::write(output_path, output_data)?;

    Ok(())
}

fn decrypt_file(
    input_path: &str,
    output_path: &str,
    passphrase: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let salt_len: usize = 22; // Length of base64 encoded salt without padding
    let encrypted_data = fs::read(input_path)?;
    let (nonce, rest) = encrypted_data.split_at(12); // 96-bit nonce
    let (salt, ciphertext) = rest.split_at(salt_len);

    let salt_str = std::str::from_utf8(salt)?;
    let key = derive_key(passphrase, salt_str)?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| "Decryption failed")?;

    fs::write(output_path, plaintext)?;

    Ok(())
}
