use anyhow::{Context, Result};
use clap::Parser;
use client_cli::config::Config;
use client_core::client::STSSClient;
use client_core::file_hasher::hash_file;
use inquire::{CustomType, Password, Select, Text};
use shared_library::server_protocol::{
    verify_timestamp_signature, Response, RsaSignature, Sha256Hash, Timestamp,
};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::ops::Deref;
use std::path::PathBuf;
use std::str::FromStr;
use indicatif::ProgressBar;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(name = "STSSClient")]
#[command(version = "1.0")]
#[command(about = "Implementation of the client from command line interface (CLI).", long_about = None)]
struct Args {
    #[arg(short, long, value_name = "config")]
    config: PathBuf,
}

macro_rules! spin_while_wait {
    ($msg:expr, $operation:expr) => {{

        let pb = ProgressBar::new_spinner();
        pb.set_message($msg);
        pb.enable_steady_tick(Duration::from_millis(100));

        let result = $operation;

        pb.finish_and_clear();

        result
    }};
}

fn timestamp_format(ts: Timestamp) -> String {
    let total_nanos: u128 = ts.get();
    const NANOS_PER_SEC: u128 = 1_000_000_000;
    let ts_seconds = (total_nanos / NANOS_PER_SEC) as i64;
    let ts_nanos = (total_nanos % NANOS_PER_SEC) as u32;

    match chrono::DateTime::from_timestamp(ts_seconds, ts_nanos) {
        Some(datetime) => datetime.format("%Y-%m-%d %H:%M:%S.%f").to_string(),
        None => format!("invalid Epoch: {}s {}ns", ts_seconds, ts_nanos),
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), anyhow::Error> {
    let args = Args::parse();

    let config = Config::from_file(args.config)
        .context("Error while reading the configuration file")?;

    let context = config
        .to_client_context()
        .context("Cannot parse the configuration file")?;

    let mut client = STSSClient::connect_from_context(context).await?;

    println!("[+] Connection established. You can now communicate with the server.");

    // Teniamo traccia dello stato per mostrare menu dinamici
    let mut is_logged_in = false;

    loop {
        // Costruiamo le opzioni del menu in base allo stato di login
        let mut options = vec!["Verify a Hash", "Exit"];
        if is_logged_in {
            options.insert(0, "Logout");
            options.insert(0, "History");
            options.insert(0, "Hash a File");
            options.insert(0, "Buy Tokens");
            options.insert(0, "Check Tokens");
        } else {
            options.insert(0, "Signup");
            options.insert(0, "Login");
        }

        println!();
        let choice = Select::new("What would you like to do?", options).prompt();

        match choice {
            Ok("Login") => {
                let user = Text::new("Username:").prompt();
                let pass = Password::new("Password:").without_confirmation().prompt();

                if let (Ok(u), Ok(p)) = (user, pass) {
                    match client.login(&u, &p).await {
                        Ok(Response::Ok) => {
                            println!("[+] Login successful!");
                            is_logged_in = true;
                        }
                        Ok(Response::LoginFailed(e)) => eprintln!("[-] Login error: {}", e),
                        Ok(Response::OperationError(msg)) => eprintln!("[-] Server error: {}", msg),
                        Ok(unexpected) => eprintln!("[!] Unexpected response: {:?}", unexpected),
                        Err(e) => eprintln!("[!] Network/client error: {}", e),
                    }
                } else {
                    eprintln!("[-] Operation cancelled.");
                }
            }

            Ok("Signup") => {
                let user = Text::new("Username:").prompt();
                let pass = Password::new("Password:").without_confirmation().prompt();

                if let (Ok(u), Ok(p)) = (user, pass) {
                    match client.signup(&u, &p).await {
                        Ok(Response::Ok) => println!("[+] Signup complete! (You can now log in)"),
                        Ok(Response::SignInFailed(e)) => eprintln!("[-] Signup error: {}", e),
                        Ok(Response::OperationError(msg)) => eprintln!("[-] Server error: {}", msg),
                        Ok(unexpected) => eprintln!("[!] Unexpected response: {:?}", unexpected),
                        Err(e) => eprintln!("[!] Network error: {:?}", e),
                    }
                } else {
                    eprintln!("[-] Operation cancelled.");
                }
            }

            Ok("Logout") => match client.logout().await {
                Ok(Response::Ok) => {
                    println!("[+] Logout successful.");
                    is_logged_in = false;
                }
                Ok(Response::NotLoggedIn) => eprintln!("[-] You are not currently logged in."),
                Ok(Response::OperationError(msg)) => eprintln!("[-] Server error: {}", msg),
                Ok(unexpected) => eprintln!("[!] Unexpected response: {:?}", unexpected),
                Err(e) => eprintln!("[!] Network/client error: {:?}", e),
            },

            Ok("Check Tokens") => match client.how_many_tokens().await {
                Ok(Response::TokenCount(count)) => println!("[+] You own {} tokens.", count),
                Ok(Response::NotLoggedIn) => eprintln!("[-] Error: you must log in first."),
                Ok(Response::OperationError(msg)) => eprintln!("[-] Server error: {}", msg),
                Ok(unexpected) => eprintln!("[!] Unexpected response: {:?}", unexpected),
                Err(e) => eprintln!("[!] Network/client error: {:?}", e),
            },

            Ok("Buy Tokens") => {
                let amount_result = CustomType::<u64>::new("Amount of tokens to buy:")
                    .with_error_message("Please enter a valid positive integer.")
                    .prompt();

                if let Ok(amount) = amount_result {
                    match client.purchase_tokens(amount).await {
                        Ok(Response::TokenCount(total)) => {
                            println!("[+] Purchase complete! You now have {} tokens.", total)
                        }
                        Ok(Response::TokenAmountTooHigh) => eprintln!("[-] Amount too high."),
                        Ok(Response::NotLoggedIn) => eprintln!("[-] Error: you must log in first."),
                        Ok(Response::OperationError(msg)) => eprintln!("[-] Server error: {}", msg),
                        Ok(unexpected) => eprintln!("[!] Unexpected response: {:?}", unexpected),
                        Err(e) => eprintln!("[!] Network/client error: {:?}", e),
                    }
                } else {
                    eprintln!("[-] Operation cancelled.");
                }
            }

            Ok("Verify a Hash") => {
                let hash_str = Text::new("Hash (SHA256):").prompt();
                let path_str = Text::new("Signature file path:").prompt();
                let ts_val = CustomType::<u128>::new("Timestamp (128-bit uint):").prompt();

                if let (Ok(h_raw), Ok(p_raw), Ok(ts_raw)) = (hash_str, path_str, ts_val) {
                    let hash = match Sha256Hash::from_str(&h_raw) {
                        Ok(h) => h,
                        Err(_) => {
                            eprintln!("[-] Invalid SHA256 Hash format.");
                            continue;
                        }
                    };

                    let sign_file_path = PathBuf::from(p_raw.trim_matches(['"', '\'']).trim());

                    let sign = match fs::read(&sign_file_path) {
                        Ok(raw_sign) => match RsaSignature::try_from(raw_sign.as_slice()) {
                            Ok(s) => s,
                            Err(_) => {
                                eprintln!("[-] Invalid signature file length for RSA.");
                                continue;
                            }
                        },
                        Err(e) => {
                            eprintln!("[-] Error reading signature file: {}", e);
                            continue;
                        }
                    };

                    let timestamp = Timestamp::new(ts_raw);

                    match verify_timestamp_signature(
                        client.server_rsa_public_key(),
                        hash,
                        timestamp,
                        &sign,
                    ) {
                        Ok(_) => println!("[+] The signature is valid and produced by the server."),
                        Err(e) => eprintln!("[-] Signature verification failed, the file was not produced by the server or some parameter(s) is(are) wrong."),
                    }
                } else {
                    eprintln!("[-] Operation cancelled.");
                }
            }

            Ok("Hash a File") => {
                let file_str = Text::new("Path of the file to hash:").prompt();
                let out_str = Text::new("Path for the output signature:").prompt();

                if let (Ok(f_raw), Ok(o_raw)) = (file_str, out_str) {
                    let file_path = PathBuf::from(f_raw.trim_matches(['"', '\'']).trim());
                    let output_path = PathBuf::from(o_raw.trim_matches(['"', '\'']).trim());

                    let mut output_file = match OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&output_path)
                    {
                        Ok(f) => f,
                        Err(e) => {
                            eprintln!("[-] Error creating output file {}: {}", output_path.display(), e);
                            continue;
                        }
                    };

                    let hash_result = match spin_while_wait!(
                        "[*] Calculating file hash...",
                        hash_file(file_path, None)
                    ) {
                        Ok(h) => h,
                        Err(e) => {
                            eprintln!("[-] Error reading the file: {:?}", e);
                            continue;
                        }
                    };

                    match spin_while_wait!(
                        "[*] Requesting signature from the server...",
                        client.timestamp_hash(hash_result).await
                    ) {
                        Ok(Response::Token { hash, sign, timestamp }) => {
                            print!(
                                "[+] Hash {} signed successfully at time: {} (formally: {}). ",
                                hash,
                                timestamp_format(timestamp),
                                timestamp,
                            );

                            if let Err(write_err) = output_file.write(sign.deref().as_ref()) {
                                println!(
                                    "\n[-] Could not write to output file: {}\nDumping to stdout (hex):\n{}",
                                    write_err, sign
                                );
                            } else {
                                println!("Signature saved to file.");
                            }

                            // Local verification
                            match verify_timestamp_signature(
                                client.server_rsa_public_key(),
                                hash_result,
                                timestamp,
                                sign.deref(),
                            ) {
                                Ok(_) => println!("[+] LOCAL VERIFICATION PASSED."),
                                Err(e) => eprintln!("[-] WARNING: Local verification failed: {:?}", e),
                            }
                        }
                        Ok(Response::NotEnoughTokens) => eprintln!("[-] Error: not enough tokens. Use 'Buy Tokens'."),
                        Ok(Response::NotLoggedIn) => eprintln!("[-] Error: you must log in first."),
                        Ok(Response::OperationError(msg)) => eprintln!("[-] Server error: {}", msg),
                        Ok(unexpected) => eprintln!("[!] Unexpected response: {:?}", unexpected),
                        Err(e) => eprintln!("[!] Network error: {:?}", e),
                    }
                } else {
                    eprintln!("[-] Operation cancelled.");
                }
            }

            Ok("History") => match client.history().await {
                Ok(Response::History(history)) => {
                    if history.is_empty() {
                        println!("No history records yet.");
                    } else {
                        println!("User History ({} records):", history.len());
                        println!("{:<22} | Signature (Truncated)", "Timestamp (UTC)");
                        println!("{:-<22}-|-{:-<35}", "", "");

                        for record in history {
                            let ts_seconds: i64 = record
                                .timestamp()
                                .get()
                                .try_into()
                                .unwrap_or_else(|_| {
                                    eprintln!(
                                        "[-] Warning: timestamp exceeds the limits that are, in \
                                         theory, sufficient forever.");
                                    0
                                });

                            let time_str = match chrono::DateTime::from_timestamp(ts_seconds, 0) {
                                Some(dt) => dt.format("%Y-%m-%d %H:%M:%S").to_string(),
                                None => format!("Invalid Epoch: {}", ts_seconds),
                            };

                            let sig_hex = hex::encode(record.hash().as_bytes());
                            let short_sig = format!("{}...{}", &sig_hex[..8], &sig_hex[sig_hex.len() - 8..]);

                            println!("{:<22} | {}", time_str, short_sig);
                        }
                    }
                }
                Ok(unexpected) => eprintln!("[!] Unexpected response: {:?}", unexpected),
                Err(e) => eprintln!("[!] Network error: {:?}", e),
            },

            Ok("Exit") | Err(_) => {
                println!("Closing the client...");
                break;
            }

            _ => {}
        }
    }

    match client.close().await {
        Ok(_) => println!("[+] Client closed successfully."),
        Err(e) => eprintln!("[!] Error while closing the client: {:?}", e),
    };

    Ok(())
}