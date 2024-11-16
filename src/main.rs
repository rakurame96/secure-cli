use clap::{Arg, ArgAction, Command};

fn main() {
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
            let output = sub_matches.get_one::<String>("output");
            println!("Encrypting file: {}", input);
            if let Some(output) = output {
                println!("Output file: {}", output);
            }
        }
        Some(("decrypt", sub_matches)) => {
            let input = sub_matches.get_one::<String>("input").unwrap();
            let output = sub_matches.get_one::<String>("output");
            println!("Decrypting file: {}", input);
            if let Some(output) = output {
                println!("Output file: {}", output);
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
}
