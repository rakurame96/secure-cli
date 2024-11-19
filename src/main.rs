use aes_gcm::aead::{Aead, KeyInit}; // Traits for encryption
use aes_gcm::{AeadCore, Aes256Gcm, Key, Nonce}; // AES-GCM encryption
use clap::{Arg, ArgAction, Command};
use std::fs;
// use std::path::Path;
use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::SaltString;
use rand::rngs::OsRng; // For secure random salt generation
use rpassword::prompt_password;

// fn derive_key_from_passphrase(passphrase: &str, salt: &[u8]) -> Vec<u8> {
    // // Argon2 configuration
    // let config = Config::default();
    
    // // Allocate a buffer to store the derived key (32 bytes for AES-256)
    // let mut key = vec![0u8; 32];
    
    // // Derive the key using Argon2
    // argon2::hash_raw(passphrase.as_bytes(), salt, &config)
    //     .expect("Failed to derive key")
    //     .copy_to(&mut key);

    // key
// }
// fn derive_key(passphrase: &str, salt: Option<&str>) -> Result<[u8; 32], Box<dyn std::error::Error>> {
//     let salt = match salt {
//         Some(s) => SaltString::from_b64(s).map_err(|e| Box::new(e.to_string()))?,
//         None => SaltString::generate(&mut OsRng),
//     };

//     let argon2 = Argon2::default();

//     let hash = argon2
//         .hash_password(passphrase.as_bytes(), &salt)
//         .map_err(|e| Box::new(e.to_string()))?;

//     let key = hash.hash.ok_or("Failed to retrieve hash bytes")?;

//     let mut key_bytes = [0u8; 32];
//     key_bytes.copy_from_slice(&key.as_bytes()[..32]);
//     Ok(key_bytes)
// }

// fn derive_key(passphrase: &str, salt: Option<&str>) -> Result<[u8; 32], Box<dyn std::error::Error>> {
//     let salt = match salt {
//         Some(s) => SaltString::from_b64(s).map_err(|e| Box::new(e.to_string()))?,
//         None => SaltString::generate(&mut OsRng),
//     };

//     let argon2 = Argon2::default();

//     let hash = argon2
//         .hash_password(passphrase.as_bytes(), &salt)
//         .map_err(|e| Box::new(e.to_string()))?;

//     let key = hash.hash.ok_or_else(|| "Failed to retrieve hash bytes".to_string())?;

//     let mut key_bytes = [0u8; 32];
//     key_bytes.copy_from_slice(&key.as_bytes()[..32]);
//     Ok(key_bytes)
// }

fn derive_key(passphrase: &str, salt: Option<&str>) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let salt = match salt {
        Some(s) => SaltString::from_b64(s).map_err(|e| {
            Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))
        })?,
        None => SaltString::generate(&mut OsRng),
    };

    let argon2 = Argon2::default();

    let hash = argon2
        .hash_password(passphrase.as_bytes(), &salt)
        .map_err(|e| {
            Box::new(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
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
        // trial 1
        // Some(("encrypt", sub_matches)) => {
        //     // let input = sub_matches.get_one::<String>("input").unwrap();
        //     // let output = sub_matches.get_one::<String>("output");
        //     // println!("Encrypting file: {}", input);
        //     let input = sub_matches.get_one::<String>("input").unwrap();
        //     let output = sub_matches
        //         .get_one::<String>("output")
        //         .unwrap_or(&format!("{}.enc", input));
        //     let key = [0u8; 32]; // Use a placeholder key for now

        //     match encrypt_file(input, output, &key) {
        //         Ok(_) => println!("File encrypted successfully: {}", output),
        //         Err(e) => eprintln!("Error encrypting file: {}", e),
        //     }
        // }
        // Some(("decrypt", sub_matches)) => {
        //     let input = sub_matches.get_one::<String>("input").unwrap();
        //     let output = sub_matches
        //         .get_one::<String>("output")
        //         .unwrap_or(&format!("{}.dec", input));
        //     let key = [0u8; 32]; // Use a placeholder key for now

        //     match decrypt_file(input, output, &key) {
        //         Ok(_) => println!("File decrypted successfully: {}", output),
        //         Err(e) => eprintln!("Error decrypting file: {}", e),
        //     }
        // }
        
        // trial 2
        // Some(("encrypt", sub_matches)) => {
        //     let input = sub_matches.get_one::<String>("input").unwrap();
            
        //     // Create a binding for the output file name
        //     let output = sub_matches
        //         .get_one::<String>("output")
        //         .map(|s| s.as_str()) // Borrow the string from matches
        //         .unwrap_or_else(|| {
        //             let formatted = format!("{}.enc", input); // Create a temporary string
        //             formatted.as_str() // Return a reference to the temporary
        //         });
            
        //     let key = [0u8; 32]; // Use a placeholder key for now
        
        //     match encrypt_file(input, output, &key) {
        //         Ok(_) => println!("File encrypted successfully: {}", output),
        //         Err(e) => eprintln!("Error encrypting file: {}", e),
        //     }
        // }
        // Some(("decrypt", sub_matches)) => {
        //     let input = sub_matches.get_one::<String>("input").unwrap();
        
        //     // Create a binding for the output file name
        //     let output = sub_matches
        //         .get_one::<String>("output")
        //         .map(|s| s.as_str())
        //         .unwrap_or_else(|| {
        //             let formatted = format!("{}.dec", input); // Create a temporary string
        //             formatted.as_str() // Return a reference to the temporary
        //         });
        
        //     let key = [0u8; 32]; // Use a placeholder key for now
        
        //     match decrypt_file(input, output, &key) {
        //         Ok(_) => println!("File decrypted successfully: {}", output),
        //         Err(e) => eprintln!("Error decrypting file: {}", e),
        //     }
        // }

        // trial 3
        Some(("encrypt", sub_matches)) => {
            let input = sub_matches.get_one::<String>("input").unwrap();
        
            // Create a binding for the output file name
            let output = sub_matches
                .get_one::<String>("output")
                .map(|s| s.to_owned()) // Clone the output string if provided
                .unwrap_or_else(|| format!("{}.enc", input)); // Use format directly
        
            // let key = [0u8; 32]; // Use a placeholder key for now
            
            // Prompt for passphrase
            let passphrase = prompt_password("Enter passphrase: ").unwrap();
            // let salt = b"fixed-salt-for-now"; // Use a fixed salt for simplicity
            let salt = SaltString::generate(&mut OsRng).to_string();
            println!("Generated Salt: {}", salt);

            // let salt_str = std::str::from_utf8(salt).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
            // let salt_str = std::str::from_utf8(salt).map_err(|e| Box::new(e.to_string()))?;
            // let salt_str = std::str::from_utf8(&salt).map_err(|e| {
            //     Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))
            // })?;
            // Derive key
            let key = derive_key(&passphrase, Some(&salt))?;

            match encrypt_file(input, &output, &key) {
                Ok(_) => println!("File encrypted successfully: {}", output),
                Err(e) => eprintln!("Error encrypting file: {}", e),
            }
        }
        Some(("decrypt", sub_matches)) => {
            let input = sub_matches.get_one::<String>("input").unwrap();
        
            // Create a binding for the output file name
            let output = sub_matches
                .get_one::<String>("output")
                .map(|s| s.to_owned()) // Clone the output string if provided
                .unwrap_or_else(|| format!("{}.dec", input)); // Use format directly
        
            // let key = [0u8; 32]; // Use a placeholder key for now
        
            // Prompt for passphrase
            let passphrase = prompt_password("Enter passphrase: ").unwrap();
            // let salt = b"fixed-salt-for-now"; // Use the same fixed salt for decryption
            
            let salt = SaltString::generate(&mut OsRng).to_string();
            println!("Generated Salt: {}", salt);

            // let salt_str = std::str::from_utf8(salt).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
            // let salt_str = std::str::from_utf8(salt).map_err(|e| {
            //     Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))
            // })?;
            // Derive key
            let key = derive_key(&passphrase, Some(&salt))?;

            match decrypt_file(input, &output, &key) {
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
) -> Result<(), Box<dyn std::error::Error>> {
    // Read the input file
    let plaintext = fs::read(input_path)?;

    // Generate a random nonce
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bit unique nonce

    // Initialize the cipher with the provided key
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));

    // Encrypt the file content
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_ref())
        .map_err(|_| "Encryption failed")?;

    // Write nonce + ciphertext to the output file
    let mut output_data = Vec::new();
    output_data.extend_from_slice(&nonce); // Store nonce at the beginning
    output_data.extend_from_slice(&ciphertext);
    fs::write(output_path, output_data)?;

    Ok(())
}

fn decrypt_file(
    input_path: &str,
    output_path: &str,
    key: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    // Read the input file
    let encrypted_data = fs::read(input_path)?;

    // Split the nonce and ciphertext
    let (nonce, ciphertext) = encrypted_data.split_at(12); // 96-bit nonce

    // Initialize the cipher with the provided key
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));

    // Decrypt the file content
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| "Decryption failed")?;

    // Write the decrypted content to the output file
    fs::write(output_path, plaintext)?;

    Ok(())
}
