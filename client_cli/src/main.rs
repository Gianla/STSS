use anyhow::{Context, Result};
use clap::Parser;
use client_cli::config::Config;
use client_core::client::STSSClient;
use client_core::file_hasher::hash_file;
use shared_library::server_protocol::Response;
use std::io::{self, Write};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "STSSClient")]
#[command(version = "1.0")]
#[command(about = "Implementation of the client from command line interface (CLI).",
          long_about = None)]
struct Args {
    #[arg(short, long, value_name = "config")]
    config: PathBuf,
}

const HELP_MSG: &str = "\
Available commands:
    login <user> <pass>
    signup <user> <pass>
    tokens
    buy <amount>
    hash <file_path>
    logout
    history
    exit/quit\
";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), anyhow::Error> {
    let args = Args::parse();

    let config =
        Config::from_file(args.config).context("Error while reading the configuration file")?;

    let context = config
        .to_client_context()
        .context("Cannot parse the configuration file")?;

    let mut stdout = io::stdout();
    let mut stderr = io::stderr();

    let mut client = STSSClient::connect_from_context(context).await?;

    writeln!(
        &mut stdout,
        "Connection established. You can now communicate with the server. Type \"help\" for a list \
        of available commands."
    )?;

    println!("{}", HELP_MSG);

    let stdin = io::stdin();

    for line_result in stdin.lines() {
        let line = line_result?;

        // Create an iterator over the words in the line.
        let mut parts = line.split_whitespace();

        // Safely extract the first word (the command).
        let command = match parts.next() {
            Some(cmd) => cmd,
            None => continue, // Ignore empty lines or lines with only spaces.
        };

        match command {
            "exit" | "quit" => {
                writeln!(&mut stdout, "Closing the client...")?;
                break;
            }

            "login" => {
                // Try to extract user and password
                if let (Some(user), Some(pass)) = (parts.next(), parts.next()) {
                    match client.login(user, pass).await {
                        Ok(Response::Ok) => writeln!(&mut stdout, "[+] Login successful!")?,
                        Ok(Response::LoginFailed(e)) => {
                            writeln!(&mut stderr, "[-] Login error: {}", e)?
                        }
                        Ok(Response::OperationError(msg)) => {
                            writeln!(&mut stderr, "[-] Server operation error: {}", msg)?
                        }
                        Ok(unexpected) => writeln!(
                            &mut stderr,
                            "[!] Unexpected server response to login: {:?}",
                            unexpected
                        )?,
                        Err(e) => writeln!(&mut stderr, "[!] Network/client error: {:?}", e)?,
                    }
                } else {
                    writeln!(&mut stderr, "Usage: login <user> <pass>")?;
                }
            }

            "signup" => {
                if let (Some(user), Some(pass)) = (parts.next(), parts.next()) {
                    match client.signup(user, pass).await {
                        Ok(Response::Ok) => writeln!(
                            &mut stdout,
                            "[+] Signup complete! (Remember you still need to log in)"
                        )?,
                        Ok(Response::SignInFailed(e)) => {
                            writeln!(&mut stderr, "[-] Signup error: {}", e)?
                        }
                        Ok(Response::OperationError(msg)) => {
                            writeln!(&mut stderr, "[-] Server operation error: {}", msg)?
                        }
                        Ok(unexpected) => writeln!(
                            &mut stderr,
                            "[!] Unexpected server response to signup: {:?}",
                            unexpected
                        )?,
                        Err(e) => writeln!(&mut stderr, "[!] Network/client error: {:?}", e)?,
                    }
                } else {
                    writeln!(&mut stderr, "Usage: signup <user> <pass>")?;
                }
            }

            "logout" => match client.logout().await {
                Ok(Response::Ok) => writeln!(&mut stdout, "[+] Logout successful.")?,
                Ok(Response::NotLoggedIn) => {
                    writeln!(&mut stderr, "[-] You are not currently logged in.")?
                }

                Ok(Response::OperationError(msg)) => {
                    writeln!(&mut stderr, "[-] Server operation error: {}", msg)?
                }

                Ok(unexpected) => writeln!(
                    &mut stderr,
                    "[!] Unexpected response to logout: {:?}",
                    unexpected
                )?,

                Err(e) => writeln!(&mut stderr, "[!] Network/client error: {:?}", e)?,
            },

            "tokens" => match client.how_many_tokens().await {
                Ok(Response::TokenCount(count)) => {
                    writeln!(&mut stdout, "[+] You own {} tokens.", count)?
                }

                Ok(Response::NotLoggedIn) => {
                    writeln!(&mut stderr, "[-] Error: you must log in first.")?
                }

                Ok(Response::OperationError(msg)) => {
                    writeln!(&mut stderr, "[-] Server operation error: {}", msg)?
                }

                Ok(unexpected) => writeln!(
                    &mut stderr,
                    "[!] Unexpected response to token request: {:?}",
                    unexpected
                )?,

                Err(e) => writeln!(&mut stderr, "[!] Network/client error: {:?}", e)?,
            },

            "buy" => {
                if let Some(amount_str) = parts.next() {
                    let amount: u64 = match amount_str.parse() {
                        Ok(n) => n,
                        Err(_) => {
                            writeln!(&mut stderr, "[-] The amount must be a positive integer.")?;
                            continue;
                        }
                    };

                    match client.purchase_tokens(amount).await {
                        Ok(Response::TokenCount(total)) => writeln!(
                            &mut stdout,
                            "[+] Purchase complete! You now have {} tokens.",
                            total
                        )?,
                        Ok(Response::TokenAmountTooHigh) => {
                            writeln!(&mut stderr, "[-] Amount too high.")?
                        }
                        Ok(Response::NotLoggedIn) => {
                            writeln!(&mut stderr, "[-] Error: you must log in first.")?
                        }
                        Ok(Response::OperationError(msg)) => {
                            writeln!(&mut stderr, "[-] Server operation error: {}", msg)?
                        }
                        Ok(unexpected) => writeln!(
                            &mut stderr,
                            "[!] Unexpected response to purchase: {:?}",
                            unexpected
                        )?,
                        Err(e) => writeln!(&mut stderr, "[!] Network/client error: {:?}", e)?,
                    }
                } else {
                    writeln!(&mut stderr, "Usage: buy <amount>")?;
                }
            }
            "hash" => {
                if let Some(path_str) = parts.next() {
                    let file_path = PathBuf::from(path_str);

                    writeln!(&mut stdout, "[*] Calculating file hash...")?;

                    let hash_result = match hash_file(file_path, None) {
                        Ok(h) => h,
                        Err(e) => {
                            writeln!(&mut stderr, "[-] Error reading the file: {:?}", e)?;
                            continue;
                        }
                    };

                    writeln!(&mut stdout, "[*] Requesting signature from the server...")?;

                    match client.timestamp_hash(hash_result).await {
                        Ok(Response::Token { sign, timestamp }) => {
                            writeln!(
                                &mut stdout,
                                "[+] Hash signed successfully! Timestamp: {}",
                                timestamp.get()
                            )?;

                            match client.verify_timestamp_signature(hash_result, timestamp, *sign) {
                                Ok(_) => writeln!(
                                    &mut stdout,
                                    "[+] LOCAL VERIFICATION PASSED: The signature is valid and was \
                                     produced by the server."
                                )?,

                                Err(e) => writeln!(
                                    &mut stderr,
                                    "[-] WARNING: Local signature verification failed: {:?}",
                                    e
                                )?,
                            }
                        }

                        Ok(Response::NotEnoughTokens) => writeln!(
                            &mut stderr,
                            "[-] Error: not enough tokens for this operation. Use the 'buy' \
                             command to recharge."
                        )?,

                        Ok(Response::NotLoggedIn) => {
                            writeln!(&mut stderr, "[-] Error: you must log in first.")?
                        }

                        Ok(Response::OperationError(msg)) => {
                            writeln!(&mut stderr, "[-] Server operation error: {}", msg)?
                        }

                        Ok(unexpected) => writeln!(
                            &mut stderr,
                            "[!] Unexpected response to hash signature request: {:?}",
                            unexpected
                        )?,

                        Err(e) => writeln!(&mut stderr, "[!] Network/client error: {:?}", e)?,
                    }
                } else {
                    writeln!(&mut stderr, "Usage: hash <file_path>")?;
                }
            }
            "history" => match client.history().await {
                Ok(Response::History(history)) => {
                    if history.is_empty() {
                        println!("No history records yet.");
                    } else {
                        println!("User History ({} records):", history.len());
                        println!("{:<22} | Signature (Truncated)", "Timestamp (UTC)");
                        println!("{:-<22}-|-{:-<35}", "", "");

                        for record in history {
                            let ts_seconds: i64 = match record.timestamp().get().try_into() {
                                Ok(val) => val,
                                Err(_) => {
                                    writeln!(
                                        &mut stderr,
                                        "[-] Warning: timestamp exceeds i64 capacity. The \
                                         universe is either exploded or a bug in the server \
                                         happened."
                                    )?;
                                    0
                                }
                            };

                            let time_str = match chrono::DateTime::from_timestamp(ts_seconds, 0) {
                                Some(datetime) => datetime.format("%Y-%m-%d %H:%M:%S").to_string(),
                                None => format!("Invalid Epoch: {}", ts_seconds),
                            };

                            let sig_hex = hex::encode(record.hash().as_bytes());

                            // Truncate the 512-character hex string for CLI readability.
                            let short_sig =
                                format!("{}...{}", &sig_hex[..8], &sig_hex[sig_hex.len() - 8..]);

                            // Print the beautifully formatted row.
                            println!("{:<22} | {}", time_str, short_sig);
                        }
                    }
                }

                Ok(unexpected) => writeln!(
                    &mut stderr,
                    "[!] Unexpected response to history request: {:?}",
                    unexpected
                )?,

                Err(e) => writeln!(&mut stderr, "[!] Network/client error: {:?}", e)?,
            },
            "help" => {
                writeln!(&mut stdout, "{}", HELP_MSG)?;
            }
            _ => {
                writeln!(
                    &mut stderr,
                    "[-] Unknown command. Usage: login, signup, tokens, buy, hash, logout, exit."
                )?;
            }
        }
    }

    match client.close().await {
        Ok(_) => writeln!(&mut stdout, "[+] Client closed successfully.")?,
        Err(e) => writeln!(&mut stderr, "[!] Error while closing the client: {:?}", e)?,
    };

    Ok(())
}
