//! Interactive PTY-shell runner that survives FortiOS 2FA prompts.
//!
//! FortiOS closes an `exec` channel the moment it prints "Email Token:" —
//! exec has no input phase. This module instead opens an interactive **PTY
//! shell**: one login (one 2FA code) lets you run a whole batch of commands.
//!
//! The 2FA flow is "auto-detect + human-in-the-loop":
//!   * when the transcript's tail shows a token prompt, we fire
//!     `prompt_tx.try_send(0)` so the GUI pops a code field;
//!   * we block on `code_rx` for the user's code and feed it back into the
//!     same live session;
//!   * a device with NO 2FA goes straight to the shell prompt and the
//!     command just runs — zero overhead.
//!
//! All of this happens on the caller's tokio runtime.

use russh::client;
use russh::client::Handler;
use russh::keys::PublicKeyOrCertificate;
use russh::ChannelMsg;
use russh::Pty;
use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;

use crate::ssh::SshArgs;

struct H;

impl Handler for H {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _k: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// Does the transcript TAIL look like a FortiGate shell prompt?
/// Admin prompt ends in `#`, read-only in `$`.
fn at_shell(transcript: &str) -> bool {
    let last = transcript.lines().next_back().unwrap_or("").trim_end();
    if last.is_empty() {
        return false;
    }
    matches!(last.chars().next_back().unwrap(), '#' | '$')
}

/// Does this freshly-arrived chunk contain a 2FA token prompt? Checking the
/// chunk (not the whole transcript) lets a re-prompt after a wrong/expired
/// code re-arm the code feed.
fn chunk_has_prompt(chunk: &str) -> bool {
    chunk.contains("Email Token")
        || chunk.contains("SMS Token")
        || chunk.contains("FortiToken")
        || chunk.contains("Token:")
}

/// Run `command` (newline-separated) over one interactive PTY shell.
///
/// * `prompt_tx`  -> GUI: fire once when a token prompt is seen.
/// * `code_rx`    <- GUI: the typed code(s). First code goes to the first
///                    prompt; a re-prompt grabs the next code.
/// * `live_tx`    -> GUI: every device chunk, for a live transcript view.
///
/// Returns the full captured transcript.
pub async fn run_interactive(
    args: &SshArgs,
    command: &str,
    prompt_tx: &mpsc::Sender<u8>,
    code_rx: &mpsc::Receiver<String>,
    live_tx: &mpsc::Sender<String>,
) -> anyhow::Result<String> {
    let config = Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(300)),
        ..<_>::default()
    });
    let mut handle =
        client::connect(config, (args.host.as_str(), args.port), H).await?;

    let auth = handle
        .authenticate_password(&args.user, &args.password)
        .await?;
    if !auth.success() {
        anyhow::bail!(
            "SSH authentication failed for user '{}' on {}:{}",
            args.user,
            args.host,
            args.port
        );
    }

    let mut channel = handle.channel_open_session().await?;
    channel
        .request_pty(
            false,
            "vanilla",
            120,
            40,
            0,
            0,
            &[(Pty::ECHO, 1)],
        )
        .await?;
    channel.request_shell(false).await?;

    let mut transcript = String::new();
    let mut stage: u8 = 0; // 0 = hunt first shell, 1 = command running, 2 = done
    let mut awaiting_code = false;
    let mut got_output = false; // true once data arrived after we sent the command
    let started = std::time::Instant::now();

    'outer: loop {
        if started.elapsed() > Duration::from_secs(300) {
            transcript.push_str("\n[timeout after 300s]");
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
                ChannelMsg::Data { data }
                | ChannelMsg::ExtendedData { data, .. } => {
                    let text = String::from_utf8_lossy(&data).to_string();
                    transcript.push_str(&text);
                    let _ = live_tx.send(text.clone());

                    // New 2FA prompt -> ask the UI for a code.
                    if chunk_has_prompt(&text) {
                        if !awaiting_code {
                            awaiting_code = true;
                            let _ = prompt_tx.send(0);
                        }
                    }

                    if awaiting_code {
                        // device is at a token prompt; don't send the command.
                        // wait for a code (handled below).
                    } else if at_shell(&transcript) {
                        match stage {
                            0 => {
                                let _ = live_tx.send(format!("\n> {command}\n"));
                                channel
                                    .data_bytes(format!("{command}\n").into_bytes())
                                    .await?;
                                stage = 1;
                            }
                            1 => {
                                if got_output {
                                    let _ = live_tx.send("\n[command finished]".to_string());
                                    channel.data_bytes(b"exit\n".to_vec()).await?;
                                    break 'outer;
                                }
                            }
                            _ => {}
                        }
                        // First data chunk after sending the command.
                        if stage == 1 && !got_output {
                            got_output = true;
                        }
                    } else {
                        // Output streaming (long result, --More-- pages, etc.).
                        got_output = true;
                    }
                }
                ChannelMsg::Eof | ChannelMsg::Close => break,
                ChannelMsg::ExitStatus { exit_status, .. } => {
                    let _ = live_tx.send(format!("\n[exit status {exit_status}]"));
                    break;
                }
                _ => {}
            }
        }

        // Feed the next typed code while the device waits for one.
        if awaiting_code {
            if let Ok(code) = code_rx.try_recv() {
                if !code.trim().is_empty() {
                    let mut buf: Vec<u8> = code.trim().as_bytes().to_vec();
                    buf.push(b'\n');
                    let _ = live_tx.send(format!("\n[> code] {trim}\n", trim = code.trim()));
                    channel.data_bytes(buf).await?;
                    awaiting_code = false;
                }
            }
        }
    }

    Ok(transcript)
}
