//! 2FA (email OTP) login probe for FortiGate — interactive PTY shell edition.
//!
//! An `exec` channel does not survive FortiOS's OTP prompt (the device closes
//! it after printing "Email Token:" because exec has no input phase). So this
//! probe opens a **PTY shell** instead:
//!
//!   1. SSH password auth
//!   2. request_pty + request_shell -> interactive FortiGate CLI
//!   3. send the (read-only) command
//!   4. if "Email Token:" appears, poll INBOX (one code per line) every 500ms
//!      and feed the fresh 6-digit code back into the same session
//!   5. capture the resulting output, then `exit`
//!
//! Usage:
//!   otp-probe.exe HOST USER PASSWORD [COMMAND] [INBOX]

use russh::client;
use russh::client::Handler;
use russh::keys::PublicKeyOrCertificate;
use russh::Pty;
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

struct Handler0;

impl Handler for Handler0 {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _k: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

fn next_unsent_code(inbox: &std::path::Path, sent: &Vec<String>) -> Option<String> {
    let data = std::fs::read_to_string(inbox).ok()?;
    // Latest line wins; skip codes already consumed this session.
    for line in data.lines().rev() {
        let code = line.trim();
        if code.is_empty() {
            continue;
        }
        if !sent.contains(&code.to_string()) {
            return Some(code.to_string());
        }
        break;
    }
    None
}

fn looks_like_prompt(capture: &str) -> bool {
    // FortiOS shell prompt: "FGVMPGLICENSEDTOCATALPA # " (admin) or
    // "FGVMPGLICENSEDTOCATALPA $ " (readonly). Judge on the LAST LINE of the
    // full transcript, not on arbitrary chunk boundaries — device output is
    // split into chunks of unpredictable size.
    let last = capture.lines().next_back().unwrap_or("").trim_end();
    if last.is_empty() {
        return false;
    }
    matches!(last.chars().next_back().unwrap(), '#' | '$')
}

/// Refuse to start if another probe instance holds the lock — parallel logins
/// against one 2FA account make the device re-fire OTP mail in rapid bursts.
fn acquire_lock(inbox: &std::path::Path) -> Option<std::fs::File> {
    let lock = inbox.with_extension("lock");
    if let Ok(f) = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock)
    {
        return Some(f);
    }
    // Lock exists: stale if older than 15 minutes.
    if let Ok(meta) = std::fs::metadata(&lock) {
        if let Ok(age) = meta.modified() {
            if age.elapsed().is_ok_and(|d| d > std::time::Duration::from_secs(15 * 60)) {
                let _ = std::fs::remove_file(&lock);
                if let Ok(f) = std::fs::OpenOptions::new().write(true).create_new(true).open(&lock) {
                    return Some(f);
                }
            }
        }
    }
    eprintln!(
        "[probe] another probe instance holds {} — refusing to start (prevents duplicate OTP mail). Kill the other one first.",
        lock.display()
    );
    None
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("usage: otp-probe.exe HOST USER PASSWORD [COMMAND] [INBOX]");
        return Ok(());
    }
    let host = args[1].clone();
    let user = args[2].clone();
    let password = args[3].clone();
    let cmd = args.get(4).cloned().unwrap_or_else(|| "show system status".to_string());
    let inbox = std::path::PathBuf::from(args.get(5).cloned().unwrap_or_else(|| {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()))
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("otp_inbox.txt")
            .to_string_lossy()
            .to_string()
    }));

    // Single-instance guard before we trigger any OTP mail.
    if acquire_lock(&inbox).is_none() {
        return Ok(());
    }

    eprintln!(
        "[probe] {user}@{host}: PTY shell, command '{cmd}', OTP inbox = {}",
        inbox.display()
    );

    let config = Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(300)),
        ..<_>::default()
    });
    let mut handle = client::connect(config, (host.as_str(), 22), Handler0).await?;

    let auth = handle.authenticate_password(&user, &password).await?;
    if !auth.success() {
        anyhow::bail!("password auth failed for '{user}'");
    }
    eprintln!("[probe] password auth OK — opening interactive shell");

    let mut channel = handle.channel_open_session().await?;
    channel
        .request_pty(
            false,
            "vanilla",
            80,
            24,
            0,
            0,
            &[(Pty::ECHO, 1)],
        )
        .await?;
    channel.request_shell(false).await?;

    let live_path = inbox.with_file_name("otp_live.txt");
    let mut live: Option<std::io::BufWriter<std::fs::File>> =
        std::fs::File::create(&live_path).map(std::io::BufWriter::new).ok();
    eprintln!("[probe] live transcript -> {}", live_path.display());

    let mut capture = String::new();
    let mut sent = Vec::new();
    let mut stage: u8 = 0; // 0=hunt prompt, 1=run cmd, 2=run exit
    let mut otp_active = false;
    let started = std::time::Instant::now();

    'outer: loop {
        if started.elapsed() > Duration::from_secs(280) {
            eprintln!("[probe] global timeout (280s)");
            break;
        }

        let tick = tokio::time::sleep(Duration::from_millis(500));
        tokio::pin!(tick);
        let maybe = tokio::select! {
            m = channel.wait() => m,
            _ = &mut tick => None,
        };

        if let Some(msg) = maybe {
            match msg {
                russh::ChannelMsg::Data { data }
                | russh::ChannelMsg::ExtendedData { data, .. } => {
                    let text = String::from_utf8_lossy(&data).to_string();
                    capture.push_str(&text);
                    if let Some(f) = live.as_mut() {
                        let _ = f.write_all(text.as_bytes());
                        let _ = f.flush();
                    }

                    // --- OTP prompt handling ---
                    if !otp_active && text.contains("Email Token") {
                        otp_active = true;
                        eprintln!("[probe] OTP prompt live — polling inbox for a fresh code…");
                    }

                    // --- normal progress: track prompt appearances ---
                    // Judge on the FULL transcript (last line), not the chunk.
                    if looks_like_prompt(&capture) {
                        if !otp_active {
                            match stage {
                                0 => {
                                    eprintln!("[probe] shell ready, sending command");
                                    channel
                                        .data_bytes(format!("{cmd}\n").into_bytes())
                                        .await?;
                                    stage = 1;
                                }
                                1 => {
                                    eprintln!("[probe] command finished — result captured");
                                    channel.data_bytes(b"exit\n".to_vec()).await?;
                                    stage = 2;
                                    break 'outer;
                                }
                                _ => {}
                            }
                        }
                    }

                    // --- feed a fresh code when waiting for OTP ---
                    if otp_active {
                        if let Some(code) = next_unsent_code(&inbox, &sent) {
                            eprintln!("[probe] sending OTP code {code}");
                            let mut buf: Vec<u8> = code.as_bytes().to_vec();
                            buf.push(b'\n');
                            channel.data_bytes(buf).await?;
                            sent.push(code);
                            otp_active = false; // wait for the next prompt
                        }
                    }
                }
                russh::ChannelMsg::Eof | russh::ChannelMsg::Close => break,
                russh::ChannelMsg::ExitStatus { exit_status, .. } => {
                    eprintln!("[probe] shell exit status {exit_status}");
                    break;
                }
                _ => {}
            }
        } else {
            // Timed tick: even without device traffic, keep polling the
            // inbox so a code that just landed gets fed promptly.
            if otp_active {
                if let Some(code) = next_unsent_code(&inbox, &sent) {
                    eprintln!("[probe] sending OTP code {code} (timed tick)");
                    let mut buf: Vec<u8> = code.as_bytes().to_vec();
                    buf.push(b'\n');
                    channel.data_bytes(buf).await?;
                    sent.push(code);
                    otp_active = false;
                }
            }
        }
    }

    println!("=== captured session transcript ===");
    print!("{capture}");
    if sent.is_empty() {
        eprintln!("\n[probe] finished WITHOUT consuming any OTP code.");
    } else {
        eprintln!(
            "\n[probe] OTP code(s) consumed: {}",
            sent.join(", ")
        );
    }
    Ok(())
}
