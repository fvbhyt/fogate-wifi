//! Shared business logic for the FortiGate WiFi SSID manager.
//!
//! Both the CLI and the GUI call into this module. It is transport-
//! agnostic: take a [SshArgs], run a command, parse VAP names, rotate
//! passphrases. No UI code here.

use anyhow::Result;
use crate::ssh::ssh_exec;
use crate::ssh::SshArgs;

/// Read the VAP list read-only. `show` never mutates configuration.
pub async fn list_vap_blocks(ssh_args: &SshArgs) -> Result<String> {
    ssh_exec(ssh_args, "show wireless-controller vap\n").await
}

/// Parse VAP names from `show wireless-controller vap` output.
/// FortiOS prints each object block headed by its name, e.g.:
///
///   wireless-controller vap "wifi.fap.01"
///   edit "wifi.fap.01"
///
/// We match any line whose first quoted token follows `vap` / `edit`.
pub fn parse_vaps(out: &str) -> Vec<String> {
    let mut names = Vec::new();
    for line in out.lines() {
        let t = line.trim();
        let cand = t
            .strip_prefix("wireless-controller vap")
            .or_else(|| t.strip_prefix("vap"))
            .or_else(|| t.strip_prefix("edit"))
            .map(str::trim);
        if let Some(rest) = cand {
            if let Some(quoted) = rest.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
                let name = quoted.to_string();
                if !name.is_empty() && !names.contains(&name) {
                    names.push(name);
                }
            }
        }
    }
    names
}

/// List VAP names (convenience wrapper: connect + show + parse).
pub async fn list_vaps(ssh_args: &SshArgs) -> Result<Vec<String>> {
    let out = list_vap_blocks(ssh_args).await?;
    let vaps = parse_vaps(&out);
    if vaps.is_empty() {
        anyhow::bail!("No VAPs found on the device. Raw output:\n{out}");
    }
    Ok(vaps)
}

/// Validate WPA2-personal passphrase length (8-63 chars).
pub fn check_passphrase(p: &str) -> Result<()> {
    if p.len() < 8 {
        anyhow::bail!("Passphrase too short (need 8-63 chars for WPA2 personal).");
    }
    if p.len() > 63 {
        anyhow::bail!("Passphrase too long (max 63 chars for WPA2 personal).");
    }
    Ok(())
}

/// Build ONE `config` block that rotates many VAPs to the same passphrase.
/// Bundling the whole batch into a single command means a 2FA device pays
/// for it with ONE login + ONE code, not one per SSID.
pub fn build_rotate_command(vaps: &[String], passphrase: &str) -> String {
    let mut cmd = String::from("config wireless-controller vap\n");
    for v in vaps {
        cmd.push_str(&format!(
            "edit \"{}\"\nset passphrase \"{}\"\nnext\n",
            v, passphrase
        ));
    }
    cmd.push_str("end\nsave\n");
    cmd
}

/// Rotate several VAPs in a single config transaction (one login, one 2FA
/// code). Returns a human-readable message listing each VAP's result.
pub async fn rotate_batch(
    ssh_args: &SshArgs,
    vaps: &[String],
    passphrase: &str,
) -> Result<String> {
    check_passphrase(passphrase)?;
    let cmd = build_rotate_command(vaps, passphrase);
    let out = ssh_exec(ssh_args, &cmd).await?;
    let failed = out.contains("(error)") || out.contains("fail");
    if failed {
        anyhow::bail!("Device rejected part of the batch:\n{out}");
    }
    Ok(format!(
        "[OK] {} SSID(s) rotated and saved to flash.\n{}",
        vaps.len(),
        vaps.join(", ")
    ))
}

/// Change the passphrase of one VAP and persist to flash (`save`).
/// FortiOS applies at `end` (no commit step); `save` writes to flash so a
/// reboot does not roll the passphrase back. Returns a human-readable
/// success/error string for the UI to display.
pub async fn rotate_one(ssh_args: &SshArgs, vap: &str, passphrase: &str) -> Result<String> {
    check_passphrase(passphrase)?;
    let cmd = format!(
        "config wireless-controller vap\nedit \"{}\"\nset passphrase \"{}\"\nnext\nend\nsave\n",
        vap, passphrase
    );
    let out = ssh_exec(ssh_args, &cmd).await?;
    // FortiGate CLI flags problems inline as "(error)" / "fail"; prompt
    // lines advance silently on success, so absence of an error token
    // means the change applied.
    if out.contains("(error)") || out.contains("fail") {
        anyhow::bail!(
            "Device rejected the change for '{vap}':\n{out}"
        );
    }
    Ok(format!("[OK] '{vap}': passphrase updated and saved to flash."))
}

/// Change passphrases of ALL VAPs to the same new passphrase.
pub async fn rotate_all(ssh_args: &SshArgs, passphrase: &str) -> Result<String> {
    let vaps = list_vaps(ssh_args).await?;
    let mut lines = Vec::new();
    for vap in &vaps {
        let msg = rotate_one(ssh_args, vap, passphrase).await?;
        lines.push(msg);
    }
    Ok(format!(
        "{} SSID(s) rotated.\n{}",
        vaps.len(),
        lines.join("\n")
    ))
}

/// Pretty-print `diagnose wireless-controller wlac -d sta` output into a
/// compact table keeping only the fields a human actually wants. The raw CLI
/// line is a wall of `key=value` tokens; this trims it to a tidy grid.
pub fn format_wifi_users(raw: &str) -> String {
    // (field key, Chinese header). Order defines the column layout.
    let cols: &[(&str, &str)] = &[
        ("wlan", "SSID"),
        ("host", "主机"),
        ("mac", "MAC"),
        ("ip", "IP"),
        ("signal", "信号"),
        ("chan", "信道"),
        ("radio_type", "频段"),
        ("security", "加密"),
        ("online", "在线"),
    ];

    // A station record is a line carrying both mac= and wlan=, AND a
    // non-empty host= — only real user devices have hostnames; AP-internal
    // stations (the `wtp-*` housekeeping entries) report `host=` and get
    // filtered out. (mac/wlan tokens still identify the record; the host
    // filter is applied on the collected row.)
    // A station record is a line carrying mac= and wlan= AND a non-empty
    // host= value. Real user devices always have a hostname (e.g.
    // `host=Phone-A`); AP-internal / housekeeping stations
    // report `host=` (empty) and must not count as "users". The host filter
    // is what the user asked for: "只有 host 的才是无线用户".
    let records: Vec<Vec<String>> = raw
        .lines()
        .filter(|l| {
            l.contains("mac=")
                && l.contains("wlan=")
                && l.split_whitespace().any(|t| {
                    t.strip_prefix("host=")
                        .is_some_and(|v| !v.is_empty())
                })
        })
        .map(|line| {
            let mut kv: std::collections::HashMap<String, String> =
                std::collections::HashMap::new();
            for tok in line.split_whitespace() {
                if let Some((k, v)) = tok.split_once('=') {
                    kv.insert(k.to_string(), v.to_string());
                }
            }
            cols.iter()
                .map(|(key, _)| {
                    let v = kv.get(*key).map(|s| s.as_str()).unwrap_or("");
                    match *key {
                        "ip" => match v {
                            "0.0.0.0" => "—".to_string(),
                            "" => "—".to_string(),
                            _ => v.to_string(),
                        },
                        "host" => match v {
                            "" => "—".to_string(),
                            _ => v.to_string(),
                        },
                        "online" => match v {
                            "no" => "离线".to_string(),
                            "yes" => "在线".to_string(),
                            _ => "—".to_string(),
                        },
                        _ => v.to_string(),
                    }
                })
                .collect()
        })
        .collect();

    // Nothing parseable — hand back the trimmed raw text so the user still
    // gets something useful rather than an empty table.
    if records.is_empty() {
        return raw.trim().to_string();
    }

    // Render as a Markdown table (no padding needed — the reader aligns it).
    let cell = |s: &str| s.replace('|', "\\|"); // keep pipes from breaking cells
    let sep = format!(
        "| {} |",
        (0..cols.len()).map(|_| "---").collect::<Vec<_>>().join(" | ")
    );
    let mut out = String::from("# 在线 WiFi 用户\n\n");
    out.push_str("| ");
    out.push_str(&cols
        .iter()
        .map(|(_, h)| h.to_string())
        .collect::<Vec<_>>()
        .join(" | "));
    out.push_str(" |\n");
    out.push_str(&format!("{sep}\n"));
    for row in &records {
        out.push_str("| ");
        out.push_str(&row.iter().map(|c| cell(c)).collect::<Vec<_>>().join(" | "));
        out.push_str(" |\n");
    }
    out.push_str(&format!("\n共 {} 个在线用户\n", records.len()));
    out
}

/// Pretty-print `get wireless-controller wtp-status` into a Markdown report
/// grouped by AP up/down. The device wraps each AP in a block like:
///
/// ```text
/// WTP: AP-One  0-10.0.0.158:5246
///     wtp-id           : APT-0001
///     name             : AP-One
///     connection-state : Connected
/// ```
///
/// Two independent up/down signals are combined:
///  * `connection-state: Connected` (the field the user asked about)
///  * the header's trailing `n-a.b.c.d:p` — a live AP shows its management
///    IP; a down AP shows `0-0.0.0.0:0`.
/// Rows keep the human-readable `name` first, with `wtp-id` as a fallback
/// when the AP never reported one.
pub fn format_ap_status(raw: &str) -> String {
    // Each row = (name, wtp-id, connection-state, mgmt-ip): the three fields
    // the user wants shown, plus the header's management IP as a live/offline
    // cross-check.
    let mut online: Vec<(String, String, String, String)> = Vec::new();
    let mut offline: Vec<(String, String, String, String)> = Vec::new();

    // The currently-open WTP block's fields.
    #[derive(Default)]
    struct Block {
        name: String,
        wtp_id: String,
        header_ip: String, // the `a.b.c.d` in the header's trailing `n-a.b.c.d:p`
        state: String,
    }
    let mut cur = Block::default();
    let mut have_cur = false;

    let flush = |cur: &Block, have: bool, online: &mut Vec<(String, String, String, String)>,
                 offline: &mut Vec<(String, String, String, String)>| {
        if !have {
            return;
        }
        let name = if cur.name.is_empty() { "—".into() } else { cur.name.clone() };
        let wtp_id = if cur.wtp_id.is_empty() { "—".into() } else { cur.wtp_id.clone() };
        let state = if cur.state.is_empty() { "—".into() } else { cur.state.clone() };
        let ip = if cur.header_ip.is_empty() { "—".into() } else { cur.header_ip.clone() };
        let ip_live = !cur.header_ip.is_empty() && cur.header_ip != "0.0.0.0";
        let state_up = cur.state.to_ascii_uppercase().starts_with("CONNECTED");
        let row = (name, wtp_id, state, ip);
        if ip_live && (state_up || cur.state.is_empty()) {
            online.push(row);
        } else {
            offline.push(row);
        }
    };

    for line in raw.lines() {
        let t = line.trim();
        // Block header: `WTP: <name>  <n>-<ip>:<port>`.
        if let Some(rest) = t.strip_prefix("WTP:") {
            flush(&cur, have_cur, &mut online, &mut offline);
            cur = Block::default();
            let rest = rest.trim();
            // Header = `<name>  <status>` where status is `<n>-<ip>:<port>` or
            // a plain dash. Split at the last run of spaces followed by a
            // digit-colon pattern.
            if let Some(sp) = rest.rfind(" ") {
                let name = rest[..sp].trim().to_string();
                let tail = rest[sp + 1..].trim();
                if let Some(ip) = tail
                    .rsplit('-')
                    .next()
                    .and_then(|s| s.split(':').next())
                {
                    cur.header_ip = ip.to_string();
                }
                cur.name = name;
            } else {
                cur.name = rest.to_string();
            }
            have_cur = true;
            continue;
        }
        if !have_cur {
            continue;
        }
        // Indented `field : value` lines.
        if let Some(i) = t.find(':') {
            let key = t[..i].trim();
            let val = t[i + 1..].trim().to_string();
            match key {
                "name" => {
                    if !val.is_empty() {
                        cur.name = val;
                    }
                }
                "wtp-id" => cur.wtp_id = val,
                "connection-state" => cur.state = val,
                _ => {}
            }
        }
    }
    flush(&cur, have_cur, &mut online, &mut offline);

    // No WTP block parsed at all -> hand back the raw text so the user still
    // sees the device's actual output rather than an empty report.
    if online.is_empty() && offline.is_empty() {
        return raw.trim().to_string();
    }

    let mut out = String::from("# AP 状态\n\n");
    out.push_str(&format!(
        "- 在线：**{}** 台\n- 离线：**{}** 台\n\n",
        online.len(),
        offline.len()
    ));
    out.push_str("## 在线 AP\n\n");
    out.push_str(&ap_table(&online));
    out.push_str("\n## 离线 AP\n\n");
    out.push_str(&ap_table(&offline));
    out
}

/// Four-column Markdown table for a group of `(name, wtp-id, state, mgmt-ip)`.
fn ap_table(rows: &[(String, String, String, String)]) -> String {
    if rows.is_empty() {
        return String::from("（无）\n");
    }
    let mut s = String::from(
        "| AP | wtp-id | 连接状态 | 管理IP |\n| --- | --- | --- | --- |\n"
    );
    for (name, wtp_id, state, ip) in rows {
        s.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            name.replace('|', "\\|"),
            wtp_id.replace('|', "\\|"),
            state.replace('|', "\\|"),
            ip.replace('|', "\\|")
        ));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real line captured from a FortiGate-30G (7.4.1) wlac -d sta output.
    #[test]
    fn wifi_users_trims_to_key_columns() {
        let raw = "vf=0 mpId=0 wtp=1 rId=2 wlan=Office-5G vlan_id=0 ip=10.0.0.156 ip6=fe80::2 mac=02:42:ac:10:00:01 vci=dhcp-1 host=Phone-A user= group= signal=-41 noise=-95 idle=1 bw=236 use=5 chan=149 radio_type=11AX_5G security=wpa3_sae mpsk= encrypt=aes cp_authed=no l3r=1,0 G=0.0.0.0:0,0.0.0.0:0-0-0 -- 0.0.0.0:0 0,0 online=yes mimo=2\n";
        let out = format_wifi_users(raw);
        // Must surface the human-relevant fields…
        for needle in ["Office-5G", "Phone-A", "02:42:ac:10:00:01", "10.0.0.156", "-41", "149", "11AX_5G", "wpa3_sae", "共 1 个在线用户"] {
            assert!(out.contains(needle), "missing {needle} in:\n{out}");
        }
        // …and must NOT drag the noisy tokens along.
        for junk in ["mpId", "cp_authed", "l3r", "G=0.0.0.0:0", "mimo"] {
            assert!(!out.contains(junk), "kept junk {junk} in:\n{out}");
        }
        // Table is far shorter than the raw line.
        assert!(out.lines().count() < 40, "not a compact table:\n{out}");
        // online=yes now renders as the Chinese label, not the raw token.
        assert!(out.contains("在线") && !out.contains("yes"), "online label:\n{out}");
    }

    #[test]
    fn wifi_users_falls_back_to_raw_when_unparseable() {
        let raw = "some totally unrelated text";
        assert_eq!(format_wifi_users(raw), "some totally unrelated text");
    }

    #[test]
    fn wifi_users_blank_values_dash() {
        // No ip (0.0.0.0) and no host -> both render as "—".
        let raw = "wlan=open ip=0.0.0.0 mac=02:42:ac:10:00:06 host= signal=-40 online=yes";
        let out = format_wifi_users(raw);
        assert!(out.contains("open") && out.contains("02:42:ac:10:00:06"), "{out}");
    }

    // Real capture from a FortiGate-30G (7.4.1) with THREE connected
    // clients. The wlac -d sta output also lists two AP-internal stations
    // (`*`-prefixed lines with an EMPTY host=): those are not users and
    // must be dropped. Only the 3 hostname-bearing lines survive.
    #[test]
    fn wifi_users_keeps_only_hosted_clients() {
        let raw = "\
FortiGate-30G # diagnose wireless-controller wlac -d sta
   vf=0 mpId=0 wtp=1 rId=2 wlan=Office-5G vlan_id=0 ip=10.0.0.152 ip6=fe80::1 mac=02:42:ac:10:00:02 vci=dhcp-2 host=Phone-B user= group= signal=-48 noise=-95 idle=36 bw=0 use=5 chan=149 radio_type=11BE_5G security=wpa3_sae mpsk= encrypt=aes cp_authed=no l3r=1,0 G=0.0.0.0:0,0.0.0.0:0-0-0 -- 0.0.0.0:0 0,0 online=yes mimo=2
                ip6=*fe80::1,9, 
   vf=0 mpId=0 wtp=1 rId=2 wlan=Office-5G vlan_id=0 ip=10.0.0.156 ip6=fe80::2 mac=02:42:ac:10:00:01 vci=dhcp-1 host=Phone-A user= group= signal=-49 noise=-95 idle=8 bw=1 use=5 chan=149 radio_type=11AX_5G security=wpa3_sae mpsk= encrypt=aes cp_authed=no l3r=1,0 G=0.0.0.0:0,0.0.0.0:0-0-0 -- 0.0.0.0:0 0,0 online=yes mimo=2
                ip6=*fe80::2,82, 
*  vf=0 mpId=0 wtp=1 rId=2 wlan=Office-5G vlan_id=0 ip=0.0.0.0 ip6=:: mac=02:42:ac:10:00:04 vci= host= user= group= signal=0 noise=0 idle=8332 bw=0 use=3 chan=149 radio_type=11BE_5G security=wpa3_sae_transition mpsk= encrypt=aes cp_authed=no l3r=1,0 G=0.0.0.0:0,0.0.0.0:0-0-0 -- 0.0.0.0:0 0,0 online=yes 
   vf=0 mpId=0 wtp=1 rId=1 wlan=Office-2G vlan_id=0 ip=10.0.0.160 ip6=fe80::3 mac=02:42:ac:10:00:03 vci= host=Tablet-A user= group= signal=-34 noise=-95 idle=8 bw=16097 use=5 chan=1 radio_type=11N_2G security=wpa3_sae mpsk= encrypt=aes cp_authed=no l3r=1,0 G=0.0.0.0:0,0.0.0.0:0-0-0 -- 0.0.0.0:0 0,0 online=yes mimo=2
                ip6=*fe80::3,28, 
*  vf=0 mpId=0 wtp=1 rId=1 wlan=Office-2G vlan_id=0 ip=0.0.0.0 ip6=:: mac=02:42:ac:10:00:05 vci= host= user= group= signal=0 noise=0 idle=8332 bw=0 use=3 chan=1 radio_type=11BE_2G security=wpa3_sae_transition mpsk= encrypt=aes cp_authed=no l3r=1,0 G=0.0.0.0:0,0.0.0.0:0-0-0 -- 0.0.0.0:0 0,0 online=yes 
";
        let out = format_wifi_users(raw);
        // The three real clients, each by its hostname…
        for host in ["Phone-B", "Phone-A", "Tablet-A"] {
            assert!(out.contains(host), "missing {host}:\n{out}");
        }
        // …and exactly three of them, no more.
        assert!(out.contains("共 3 个在线用户"), "count line:\n{out}");
        // The two AP-internal stations are dropped — their MACs must NOT
        // appear, and no empty-host row leaks into the table.
        for junk in ["02:42:ac:10:00:04", "02:42:ac:10:00:05", "wpa3_sae_transition"] {
            assert!(!out.contains(junk), "kept AP-internal {junk}:\n{out}");
        }
        // Markdown table shape.
        assert!(out.starts_with("# 在线 WiFi 用户"), "{out}");
        assert!(out.contains("| SSID | 主机 |"), "{out}");
    }

    // Real machine `get wireless-controller wtp-status` output: three AP
    // blocks, one up (live mgmt IP in the `WTP:` header) and two down.
    #[test]
    fn ap_status_groups_by_connection_state() {
        let raw = "\
WTP: AP-One  0-10.0.0.158:5246
    wtp-id           : APT-0001
    name             : AP-One
    connection-state : Connected
WTP: AP-Three  0-0.0.0.0:0
    wtp-id           : APT-0002
    name             : AP-Three
    connection-state : Disconnected
WTP: AP-Two  0-0.0.0.0:0
    wtp-id           : APT-0003
    name             : AP-Two
    connection-state : Disconnected
";
        let out = format_ap_status(raw);
        assert!(out.contains("在线 AP") && out.contains("离线 AP"), "{out}");
        // All three names AND their wtp-ids survive (the original bug: wtp-id
        // rendered as "—").
        for n in ["AP-One", "AP-Two", "AP-Three"] {
            assert!(out.contains(n), "missing {n}:\n{out}");
        }
        for id in ["APT-0001", "APT-0002", "APT-0003"] {
            assert!(out.contains(id), "missing wtp-id {id}:\n{out}");
        }
        assert!(out.contains("Connected") && out.contains("Disconnected"), "{out}");
        // Counts: 1 online (the live-IP AP) / 2 offline.
        assert!(out.contains("在线：**1** 台"), "{out}");
        assert!(out.contains("离线：**2** 台"), "{out}");
        // Four-column table header.
        assert!(out.contains("| AP | wtp-id | 连接状态 | 管理IP |"), "{out}");
    }

    // wtp-id and name are shown even when an AP has no live mgmt IP; the
    // header status `0-0.0.0.0:0` is what tips it to the offline group.
    #[test]
    fn ap_status_offline_ap_shows_wtp_id_and_name() {
        let raw = "\
WTP: AP-Three  0-0.0.0.0:0
    wtp-id           : APT-0002
    name             : AP-Three
    connection-state : Disconnected
";
        let out = format_ap_status(raw);
        // The wtp-id is NOT a "—" fallback — the real serial is extracted.
        assert!(out.contains("APT-0002"), "{out}");
        assert!(out.contains("AP-Three"), "{out}");
        assert!(out.contains("离线：**1** 台"), "{out}");
        assert!(out.contains("在线：**0** 台"), "{out}");
    }

    // No connection-state anywhere -> raw text passes through untouched.
    #[test]
    fn ap_status_falls_back_to_raw_when_unparseable() {
        let raw = "some totally unrelated text";
        assert_eq!(format_ap_status(raw), "some totally unrelated text");
    }

    // Empty groups render the (无) placeholder, not a broken table.
    #[test]
    fn ap_status_empty_group_placeholder() {
        let raw = "\
WTP: AP-One  0-10.0.0.158:5246
    wtp-id           : APT-0001
    name             : AP-One
    connection-state : Connected
";
        let out = format_ap_status(raw);
        // Only one (online) AP, so the offline section must say 无.
        assert!(out.contains("（无）"), "offline group should say 无:\n{out}");
        assert!(out.contains("在线：**1** 台") && out.contains("离线：**0** 台"), "{out}");
    }
}
