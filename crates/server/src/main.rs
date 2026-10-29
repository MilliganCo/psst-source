use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use pwd_server::{create_invite, init_data, link, open_state, tls, Config};

/// Passwords sync server. Stores only encrypted data.
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// Data directory (database, certificate, releases).
    #[arg(long, global = true, env = "PWD_DATA", default_value = "pwd-data")]
    data: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create the data directory and print the first admin invite.
    Init {
        /// Name or IP clients use to reach this server.
        #[arg(long)]
        host: String,
        #[arg(long, default_value_t = 8443)]
        port: u16,
    },
    /// Run the server.
    Serve {
        /// Address to listen on.
        #[arg(long, default_value = "0.0.0.0")]
        bind: String,
    },
    /// Print a one-time invite link (valid 7 days).
    Invite {
        #[arg(long)]
        admin: bool,
    },
    /// Print the link for logging in on a new device.
    Link,
    /// List users, or block / unblock one.
    Users {
        #[arg(long)]
        disable: Option<String>,
        #[arg(long)]
        enable: Option<String>,
    },
    /// Write a consistent copy of the database.
    Backup { file: PathBuf },
    /// Publish a release: the files in DIR (installers, .sig, latest.json) replace the previous ones.
    Release { dir: PathBuf },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let data = cli.data;
    match cli.cmd {
        Cmd::Init { host, port } => {
            let cfg = init_data(&data, &host, port)?;
            let st = open_state(&data)?;
            let fp = tls::fingerprint(&data)?;
            println!("Data directory: {}", data.display());
            println!("Start the server:   pwd-server --data {} serve", data.display());
            // Running init again (new address, update) keeps users; only a fresh server gets an admin invite.
            if st.users()?.is_empty() {
                println!("Admin invite (one-time, 7 days):\n\n  {}\n", link(&cfg, &fp, Some(&create_invite(&st, true)?)));
            } else {
                println!("Address updated: {}", link(&cfg, &fp, None));
            }
        }
        Cmd::Serve { bind } => {
            let cfg = Config::load(&data)?;
            let st = Arc::new(open_state(&data)?);
            let addr: SocketAddr = format!("{bind}:{}", cfg.port).parse()?;
            println!("pwd-server listening on https://{addr}  (link: {})", link(&cfg, &tls::fingerprint(&data)?, None));
            tokio::runtime::Runtime::new()?.block_on(pwd_server::serve(st, &data, addr, axum_server::Handle::new()))?;
        }
        Cmd::Invite { admin } => {
            let cfg = Config::load(&data)?;
            let st = open_state(&data)?;
            println!("{}", link(&cfg, &tls::fingerprint(&data)?, Some(&create_invite(&st, admin)?)));
        }
        Cmd::Link => {
            let cfg = Config::load(&data)?;
            println!("{}", link(&cfg, &tls::fingerprint(&data)?, None));
        }
        Cmd::Users { disable, enable } => {
            let st = open_state(&data)?;
            for (name, off) in [(disable, true), (enable, false)] {
                if let Some(name) = name {
                    let found = st.set_disabled(&name, off)?;
                    println!("{name}: {}", if !found { "not found" } else if off { "blocked" } else { "unblocked" });
                }
            }
            for u in st.users()? {
                println!("{:<24} {}{}", u.username, if u.is_admin { "admin" } else { "user" }, if u.disabled { ", blocked" } else { "" });
            }
        }
        Cmd::Backup { file } => {
            open_state(&data)?.backup(&file)?;
            println!("Backup written to {}", file.display());
        }
        Cmd::Release { dir } => {
            for f in pwd_server::publish_release(&data, &dir)? {
                println!("published {f}");
            }
        }
    }
    Ok(())
}
