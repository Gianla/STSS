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
#[command(about = "Implementation of the client from command line interface (CLI).", long_about = None)]
struct Args {
    #[arg(short, long, value_name = "config")]
    file: PathBuf,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), anyhow::Error> {
    let args = Args::parse();

    let config =
        Config::from_file(args.file).context("Error while reading the configuration file")?;

    let context = config
        .to_client_context()
        .context("Cannot parse the configuration file")?;

    let mut stdout = io::stdout();
    let mut stderr = io::stderr();

    let mut client = STSSClient::connect_from_context(context).await?;

    writeln!(
        &mut stdout,
        "Connessione stabilita! Puoi inserire i comandi."
    )?;
    writeln!(&mut stdout, "Comandi disponibili:")?;
    writeln!(&mut stdout, "  login <user> <pass>")?;
    writeln!(&mut stdout, "  signup <user> <pass>")?;
    writeln!(&mut stdout, "  tokens")?;
    writeln!(&mut stdout, "  buy <amount>")?;
    writeln!(&mut stdout, "  hash <percorso_file>")?;
    writeln!(&mut stdout, "  logout")?;
    writeln!(&mut stdout, "  exit")?;
    writeln!(&mut stdout, "-----------------------------------")?;

    let stdin = io::stdin();

    for line_result in stdin.lines() {
        let line = line_result?;
        let args: Vec<&str> = line.split_whitespace().collect();

        if args.is_empty() {
            continue;
        }

        match args[0] {
            "exit" | "quit" => {
                writeln!(&mut stdout, "Chiusura del client...")?;
                break;
            }
            "login" => {
                if args.len() < 3 {
                    writeln!(&mut stderr, "Uso: login <user> <pass>")?;
                    continue;
                }
                match client.login(args[1], args[2]).await {
                    Ok(Response::Ok) => {
                        writeln!(&mut stdout, "[+] Login effettuato con successo!")?
                    }
                    Ok(Response::LoginFailed(e)) => {
                        writeln!(&mut stderr, "[-] Errore di login: {}", e)?
                    }
                    Ok(Response::OperationError(msg)) => {
                        writeln!(&mut stderr, "[-] Errore operativo dal server: {}", msg)?
                    }
                    Ok(unexpected) => writeln!(
                        &mut stderr,
                        "[!] Risposta inaspettata dal server al login: {:?}",
                        unexpected
                    )?,
                    Err(e) => writeln!(&mut stderr, "[!] Errore di rete/client: {:?}", e)?,
                }
            }
            "signup" => {
                if args.len() < 3 {
                    writeln!(&mut stderr, "Uso: signup <user> <pass>")?;
                    continue;
                }
                match client.signup(args[1], args[2]).await {
                    Ok(Response::Ok) => writeln!(
                        &mut stdout,
                        "[+] Registrazione completata! (Ricorda che devi fare il login)"
                    )?,
                    Ok(Response::SignInFailed(e)) => {
                        writeln!(&mut stderr, "[-] Errore di registrazione: {}", e)?
                    }
                    Ok(Response::OperationError(msg)) => {
                        writeln!(&mut stderr, "[-] Errore operativo dal server: {}", msg)?
                    }
                    Ok(unexpected) => writeln!(
                        &mut stderr,
                        "[!] Risposta inaspettata dal server al signup: {:?}",
                        unexpected
                    )?,
                    Err(e) => writeln!(&mut stderr, "[!] Errore di rete/client: {:?}", e)?,
                }
            }
            "logout" => match client.logout().await {
                Ok(Response::Ok) => writeln!(&mut stdout, "[+] Logout effettuato.")?,
                Ok(Response::NotLoggedIn) => {
                    writeln!(&mut stderr, "[-] Non sei attualmente loggato.")?
                }
                Ok(Response::OperationError(msg)) => {
                    writeln!(&mut stderr, "[-] Errore operativo dal server: {}", msg)?
                }
                Ok(unexpected) => writeln!(
                    &mut stderr,
                    "[!] Risposta inaspettata al logout: {:?}",
                    unexpected
                )?,
                Err(e) => writeln!(&mut stderr, "[!] Errore di rete/client: {:?}", e)?,
            },
            "tokens" => match client.how_many_tokens().await {
                Ok(Response::TokenCount(count)) => {
                    writeln!(&mut stdout, "[+] Possiedi {} token.", count)?
                }
                Ok(Response::NotLoggedIn) => {
                    writeln!(&mut stderr, "[-] Errore: devi prima fare il login.")?
                }
                Ok(Response::OperationError(msg)) => {
                    writeln!(&mut stderr, "[-] Errore operativo dal server: {}", msg)?
                }
                Ok(unexpected) => writeln!(
                    &mut stderr,
                    "[!] Risposta inaspettata alla richiesta token: {:?}",
                    unexpected
                )?,
                Err(e) => writeln!(&mut stderr, "[!] Errore di rete/client: {:?}", e)?,
            },
            "buy" => {
                if args.len() < 2 {
                    writeln!(&mut stderr, "Uso: buy <quantità>")?;
                    continue;
                }
                let amount: u64 = match args[1].parse() {
                    Ok(n) => n,
                    Err(_) => {
                        writeln!(
                            &mut stderr,
                            "[-] La quantità deve essere un numero intero positivo."
                        )?;
                        continue;
                    }
                };

                match client.purchase_tokens(amount).await {
                    Ok(Response::TokenCount(total)) => writeln!(
                        &mut stdout,
                        "[+] Acquisto completato! Ora hai {} token.",
                        total
                    )?,
                    Ok(Response::TokenAmountTooHigh) => {
                        writeln!(&mut stderr, "[-] Quantità troppo alta.")?
                    }
                    Ok(Response::NotLoggedIn) => {
                        writeln!(&mut stderr, "[-] Errore: devi prima fare il login.")?
                    }
                    Ok(Response::OperationError(msg)) => {
                        writeln!(&mut stderr, "[-] Errore operativo dal server: {}", msg)?
                    }
                    Ok(unexpected) => writeln!(
                        &mut stderr,
                        "[!] Risposta inaspettata all'acquisto: {:?}",
                        unexpected
                    )?,
                    Err(e) => writeln!(&mut stderr, "[!] Errore di rete/client: {:?}", e)?,
                }
            }
            "hash" => {
                if args.len() < 2 {
                    writeln!(&mut stderr, "Uso: hash <percorso_file>")?;
                    continue;
                }

                let file_path = PathBuf::from(args[1]);

                writeln!(&mut stdout, "[*] Calcolo dell'hash del file in corso...")?;
                let hash_result = match hash_file(file_path, None) {
                    Ok(h) => h,
                    Err(e) => {
                        writeln!(
                            &mut stderr,
                            "[-] Errore durante la lettura del file: {:?}",
                            e
                        )?;
                        continue;
                    }
                };

                writeln!(&mut stdout, "[*] Richiesta della firma al server...")?;
                match client.timestamp_hash(hash_result).await {
                    Ok(Response::Token { sign, timestamp }) => {
                        writeln!(
                            &mut stdout,
                            "[+] Hash firmato con successo! Timestamp: {}",
                            timestamp.get()
                        )?;

                        match client.verify_timestamp_signature(&hash_result, timestamp, &sign) {
                            Ok(_) => writeln!(
                                &mut stdout,
                                "[+] VERIFICA LOCALE SUPERATA: La firma è valida ed è stata prodotta dal server."
                            )?,
                            Err(e) => writeln!(
                                &mut stderr,
                                "[-] ATTENZIONE: La verifica locale della firma è fallita: {:?}",
                                e
                            )?,
                        }
                    }
                    Ok(Response::NotEnoughTokens) => writeln!(
                        &mut stderr,
                        "[-] Errore: non hai abbastanza token per questa operazione. Usare il comando 'buy' per ricaricare."
                    )?,
                    Ok(Response::NotLoggedIn) => {
                        writeln!(&mut stderr, "[-] Errore: devi prima fare il login.")?
                    }
                    Ok(Response::OperationError(msg)) => {
                        writeln!(&mut stderr, "[-] Errore operativo dal server: {}", msg)?
                    }
                    Ok(unexpected) => writeln!(
                        &mut stderr,
                        "[!] Risposta inaspettata alla richiesta di sign: {:?}",
                        unexpected
                    )?,
                    Err(e) => writeln!(&mut stderr, "[!] Errore di rete/client: {:?}", e)?,
                }
            }
            _ => {
                writeln!(
                    &mut stderr,
                    "[-] Comando sconosciuto. Usa: login, signup, tokens, buy, hash, logout, exit."
                )?;
            }
        }
    }

    Ok(())
}
