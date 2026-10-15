//! CLI binary for fogate-wifi.
use clap::{CommandFactory, Parser};
use fogate_wifi::core;
use fogate_wifi::ssh::SshArgs;

#[derive(Parser, Debug)]
#[command(name = "fogate-wifi", version, about = "Manage FortiGate WiFi SSID passwords over SSH")]
struct Cli {
    /// FortiGate host (IP or hostname)
    host: String,

    /// SSH port
    #[arg(short, long, default_value_t = 22)]
    port: u16,

    /// SSH admin username
    #[arg(short, long)]
    user: String,

    /// SSH password (prompted if omitted; long form only to avoid clashing with -p port)
    #[arg(long)]
    password: Option<String>,

    /// List SSIDs
    #[arg(long, conflicts_with_all = &["change", "all"])]
    list: bool,

    /// Change password of a specific VAP
    #[arg(long, conflicts_with_all = &["list", "all"])]
    change: Option<String>,

    /// New passphrase
    #[arg(long)]
    new: Option<String>,

    /// Change all SSIDs to the same new passphrase
    #[arg(long, conflicts_with_all = &["list", "change"])]
    all: bool,

    /// Run an arbitrary read-only CLI command (e.g. "show user setting")
    #[arg(long, conflicts_with_all = &["list", "change", "all"])]
    run: Option<String>,

    /// Print the raw device response
    #[arg(long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let password = match cli.password {
        Some(p) => p,
        None => rpassword::prompt_password(&format!(
            "SSH password for {u}@{h} ({p}): ",
            u = cli.user,
            h = cli.host,
            p = cli.port
        ))?,
    };

    let ssh_args = SshArgs {
        host: cli.host.clone(),
        port: cli.port,
        user: cli.user.clone(),
        password,
    };

    // --- list mode ---
    if cli.list {
        let out = core::list_vap_blocks(&ssh_args).await?;
        let vaps = core::parse_vaps(&out);
        if vaps.is_empty() {
            println!("(no VAPs found — raw output:\n{out}");
        }
        let max = vaps.iter().map(|v| v.len()).max().unwrap_or(0);
        for (i, v) in vaps.iter().enumerate() {
            println!("{:<width$}  #{}", v, i + 1, width = max + 2);
        }
        println!("\nFound {} SSID(s).", vaps.len());
        println!("Rotate one:  fogate-wifi {host} -u {user} --change <name> [--new <pass>]", host = ssh_args.host, user = ssh_args.user);
        println!("Rotate all:  fogate-wifi {host} -u {user} --all [--new <pass>]", host = ssh_args.host, user = ssh_args.user);
        return Ok(());
    }

    // --- change one ---
    if let Some(vap_name) = &cli.change {
        let passphrase = match &cli.new {
            Some(n) => n.clone(),
            None => rpassword::prompt_password(&format!("New passphrase (for VAP '{vap_name}'): "))?,
        };
        core::check_passphrase(&passphrase)?;
        let msg = core::rotate_one(&ssh_args, vap_name, &passphrase).await?;
        if cli.verbose {
            eprintln!("{msg}");
        } else {
            println!("{msg}");
        }
        return Ok(());
    }

    // --- change all ---
    if cli.all {
        let passphrase = match &cli.new {
            Some(n) => n.clone(),
            None => rpassword::prompt_password("New passphrase (applied to ALL SSIDs): ")?,
        };
        core::check_passphrase(&passphrase)?;
        let msg = core::rotate_all(&ssh_args, &passphrase).await?;
        println!("{msg}");
        return Ok(());
    }

    // --- run a raw command (diagnostic; only use read-only commands) ---
    if let Some(cmd) = &cli.run {
        let out = fogate_wifi::ssh::ssh_exec(&ssh_args, cmd).await?;
        print!("{out}");
        return Ok(());
    }

    Cli::command().print_help()?;
    Ok(())
}
