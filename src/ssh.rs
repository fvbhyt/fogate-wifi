//! Minimal SSH exec helper built on russh.
//!
//! Connects to a FortiGate over SSH, authenticates with a password,
//! executes a command through a session channel and returns the combined
//! stdout/stderr text. FortiGate's CLI is line-based, so commands are
//! newline-separated.

use russh::client;
use russh::client::Handler;
use russh::keys::PublicKeyOrCertificate;
use russh::ChannelMsg;
use std::sync::Arc;
use std::time::Duration;

pub struct SshArgs {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
}

struct Handler0;

impl Handler for Handler0 {
    type Error = russh::Error;

    /// v0.1: accept any host key (in-house device). A production build
    /// should pin the key here.
    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// Run `command` (newline-separated) over SSH and return all output.
pub async fn ssh_exec(args: &SshArgs, command: &str) -> anyhow::Result<String> {
    let config = Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(120)),
        ..<_>::default()
    });
    let mut handle =
        client::connect(config, (args.host.as_str(), args.port), Handler0).await?;

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
    channel.exec(false, command).await?;

    let mut output = String::new();
    let mut exit_code: Option<u32> = None;
    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::Data { ref data } => {
                output.push_str(&String::from_utf8_lossy(data));
            }
            ChannelMsg::ExtendedData { ref data, .. } => {
                output.push_str(&String::from_utf8_lossy(data));
            }
            ChannelMsg::ExitStatus {
                exit_status,
                ..
            } => {
                exit_code = Some(exit_status);
                break;
            }
            ChannelMsg::Eof | ChannelMsg::Close => break,
            _ => {}
        }
    }
    if let Some(code) = exit_code {
        if code != 0 {
            eprintln!("(shell exit code: {code})");
        }
    }
    Ok(output)
}
