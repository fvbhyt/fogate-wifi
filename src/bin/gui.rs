//! Native egui window for fogate-wifi — the "click a few buttons" UI.
//!
//! Layout: IP / port / user / password inputs, a "connect & list SSIDs"
//! button, a checkbox list of VAPs, a new-passphrase field and a
//! "save" button. All SSH work happens on a dedicated worker thread with
//! its own tokio runtime; jobs cross via an mpsc channel so russh's
//! (non-Send) futures never have to move between threads.

#![cfg_attr(windows, windows_subsystem = "windows")]

use eframe::egui;
use std::collections::VecDeque;
use std::sync::mpsc;
use std::sync::mpsc::Sender;
use std::sync::Mutex;

use fogate_wifi::core;
use fogate_wifi::ssh::SshArgs;
use fogate_wifi::ssh2fa::run_interactive;

/// Where connection settings persist between runs.
const CONFIG_PATH: &str = "fogate-wifi-config.json";

#[derive(serde::Serialize, serde::Deserialize)]
struct SavedConfig {
    host: String,
    port: String,
    user: String,
    password: String,
}

fn config_dir() -> std::path::PathBuf {
    let base = std::env::var("LOCALAPPDATA")
        .unwrap_or_else(|_| std::env::var("APPDATA").unwrap_or_else(|_| "C:\\Users\\Public".to_string()));
    let dir = std::path::Path::new(&base).join("fogate-wifi");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn load_config() -> Option<SavedConfig> {
    let path = config_dir().join(CONFIG_PATH);
    let bytes = std::fs::read(&path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn save_config(cfg: &SavedConfig) {
    let path = config_dir().join(CONFIG_PATH);
    if let Ok(json) = serde_json::to_string_pretty(cfg) {
        let _ = std::fs::write(&path, json);
    }
}

fn delete_config() {
    let path = config_dir().join(CONFIG_PATH);
    let _ = std::fs::remove_file(&path);
}

/// Directory that contains the running .exe — wherever the user copied the
/// program into. Reports land here. Falls back to the current dir.
fn exe_dir() -> std::path::PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default())
}

/// Load the system's Microsoft YaHei (msyh.ttc) into egui so CJK text
/// renders instead of tofu boxes. egui's built-in fonts only cover
/// Latin glyphs.
fn install_cjk_fonts(cc: &eframe::CreationContext<'_>) {
    let candidates = [
        std::path::Path::new("C:\\Windows\\Fonts\\msyh.ttc"),
        std::path::Path::new("C:\\Windows\\Fonts\\simhei.ttf"),
    ];
    for path in &candidates {
        match std::fs::read(path) {
            Ok(bytes) => {
                let font_data = egui::FontData::from_owned(bytes);
                let mut defs = egui::FontDefinitions::default();
                defs.font_data.insert("CJK".into(), std::sync::Arc::new(font_data));
                // Prepend to both families so CJK glyphs fall back to YaHei
                // while Latin text keeps its native metrics.
                defs.families
                    .entry(egui::FontFamily::Proportional)
                    .or_default()
                    .insert(0, "CJK".to_string());
                defs.families
                    .entry(egui::FontFamily::Monospace)
                    .or_default()
                    .insert(0, "CJK".to_string());
                cc.egui_ctx.set_fonts(defs);
                return;
            }
            Err(_) => continue,
        }
    }
    // No CJK font found — fall back to whatever egui ships (tofu for CJK).
}

/// What a finished worker job hands back to the UI.
enum JobOutcome {
    List(Vec<String>),
    Msg(String),
}

/// A command sent to the worker thread.
enum Job {
    List(SshArgs),
    Rotate {
        args: SshArgs,
        names: Vec<String>,
        pass: String,
    },
    /// Run one read-only diagnostic command and save its full output to a
    /// timestamped file NEXT TO THE EXE (whatever folder the user dropped
    /// the program into).
    Snapshot {
        args: SshArgs,
        label: String,
        command: String,
    },
}

/// Minimal local-time stamp (yyyymmdd-HHmmss) without pulling in chrono:
/// civil-from-days algorithm, offset UTC+8 (China).
fn stamp_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64;
    let utc8 = secs + 8 * 3600;
    let days = utc8 / 86400;
    let sod = utc8 % 86400;
    let h = sod / 3600;
    let m = (sod % 3600) / 60;
    let s = sod % 60;
    // civil calendar (days since 1970-01-01), all i64 to avoid mixed ops
    let (y, mo, d) = {
        let z = days + 719468;
        let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
        let doe = z - era * 146097;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let mo = if mp < 10 { mp + 2 } else { mp - 10 };
        (y + (if mo <= 2 { 1 } else { 0 }), mo, d)
    };
    format!("{y:04}{mo:02}{d:02}-{h:02}{m:02}{s:02}")
}

/// Start the worker thread (owns its own tokio runtime). Returns:
///   * job_tx / result_rx  — request/response
///   * prompt_rx           — worker -> UI "a 2FA code is needed now"
///   * code_tx             — UI    -> worker the typed code
///   * live_rx             — worker -> UI live device transcript
fn start_worker() -> (
    Sender<Job>,
    mpsc::Receiver<std::result::Result<JobOutcome, String>>,
    mpsc::Receiver<u8>,
    Sender<String>,
    mpsc::Receiver<String>,
) {
    let (job_tx, job_rx) = mpsc::channel();
    let (result_tx, result_rx) = mpsc::channel();
    let (prompt_tx, prompt_rx) = mpsc::channel::<u8>();
    let (code_tx, code_rx) = mpsc::channel::<String>();
    let (live_tx, live_rx) = mpsc::channel::<String>();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        while let Ok(job) = job_rx.recv() {
            // A single interactive PTY shell per job: one login (one 2FA
            // code) covers the whole command. Non-2FA devices never see the
            // prompt and just run — zero overhead.
            let outcome: std::result::Result<JobOutcome, String> = match job {
                Job::List(args) => match rt.block_on(run_interactive(
                    &args,
                    "show wireless-controller vap\n",
                    &prompt_tx,
                    &code_rx,
                    &live_tx,
                )) {
                    Ok(out) => {
                        let vaps = core::parse_vaps(&out);
                        if vaps.is_empty() {
                            Err("No VAPs found on the device.\n{out}".into())
                        } else {
                            Ok(JobOutcome::List(vaps))
                        }
                    }
                    Err(e) => Err(e.to_string()),
                },
                Job::Rotate { args, names, pass } => {
                    if let Err(e) = core::check_passphrase(&pass) {
                        Err(e.to_string())
                    } else {
                        let cmd = core::build_rotate_command(&names, &pass);
                        match rt.block_on(run_interactive(
                            &args,
                            &cmd,
                            &prompt_tx,
                            &code_rx,
                            &live_tx,
                        )) {
                            Ok(out) => {
                                if out.contains("(error)") || out.contains("fail") {
                                    Err(format!("Device rejected the change:\n{out}"))
                                } else {
                                    Ok(JobOutcome::Msg(format!(
                                        "成功！{} 个 SSID 的新密码已保存（设备重启也不会丢）。",
                                        names.len()
                                    )))
                                }
                            }
                            Err(e) => Err(e.to_string()),
                        }
                    }
                }
                Job::Snapshot { args, label, command } => {
                    match rt.block_on(run_interactive(
                        &args,
                        &command,
                        &prompt_tx,
                        &code_rx,
                        &live_tx,
                    )) {
                        Ok(out) => {
                            // Both snapshots are reformatted into tidy
                            // Markdown before they land on disk:
                            //  * wifi_users — a wall of `key=value` tokens -> table
                            //  * ap_status  — wtp blocks -> online/offline groups
                            let content = match label.as_str() {
                                "wifi_users" => core::format_wifi_users(&out),
                                "ap_status" => core::format_ap_status(&out),
                                _ => out,
                            };
                            let file = exe_dir()
                                .join(format!("{label}_{}.md", stamp_now()));
                            match std::fs::write(&file, &content) {
                                Ok(_) => Ok(JobOutcome::Msg(format!(
                                    "已保存「{label}」到：\n{}",
                                    file.display()
                                ))),
                                Err(e) => Err(format!(
                                    "命令已执行，但写入文件失败（{e}）。内容在下方实时回显区可见。"
                                )),
                            }
                        }
                        Err(e) => Err(e.to_string()),
                    }
                }
            };
            if result_tx.send(outcome).is_err() {
                break; // UI window closed
            }
        }
    });
    (job_tx, result_rx, prompt_rx, code_tx, live_rx)
}

struct GuiApp {
    host: String,
    port_str: String,
    user: String,
    password: String,
    remember: bool,

    job_tx: Sender<Job>,
    result_rx: mpsc::Receiver<std::result::Result<JobOutcome, String>>,
    pending: usize,
    status: String,

    // 2FA human-in-the-loop
    prompt_rx: Mutex<mpsc::Receiver<u8>>,
    code_tx: Mutex<Sender<String>>,
    need_code: bool,
    code: String,
    code_hint: String,

    // live device transcript
    live_rx: Mutex<mpsc::Receiver<String>>,
    live_log: VecDeque<String>,

    vaps: Vec<String>,
    selected: Vec<bool>,
    new_pass: String,
}

impl GuiApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        install_cjk_fonts(cc);
        let (job_tx, result_rx, prompt_rx, code_tx, live_rx) = start_worker();

        // Restore previously saved connection info (empty defaults on
        // first run — nothing is hard-coded).
        let saved = load_config();
        let (host, port_str, user, password, remember) = match saved {
            Some(cfg) => {
                let remember = !cfg.password.is_empty();
                (
                    cfg.host,
                    if cfg.port.is_empty() { "22".into() } else { cfg.port },
                    cfg.user,
                    cfg.password,
                    remember,
                )
            }
            None => (String::new(), "22".into(), String::new(), String::new(), false),
        };

        Self {
            host,
            port_str,
            user,
            password,
            remember,
            job_tx,
            result_rx,
            pending: 0,
            status: "填写设备信息后，点「连接并读取 SSID」。".into(),
            prompt_rx: Mutex::new(prompt_rx),
            code_tx: Mutex::new(code_tx),
            need_code: false,
            code: String::new(),
            code_hint: String::new(),
            live_rx: Mutex::new(live_rx),
            live_log: VecDeque::new(),
            vaps: Vec::new(),
            selected: Vec::new(),
            new_pass: String::new(),
        }
    }

    fn persist(&self) {
        if self.remember {
            save_config(&SavedConfig {
                host: self.host.trim().to_string(),
                port: self.port_str.trim().to_string(),
                user: self.user.trim().to_string(),
                password: self.password.clone(),
            });
        } else {
            // Unchecked -> wipe any previously stored credentials.
            delete_config();
        }
    }

    fn ssh_args(&self) -> SshArgs {
        SshArgs {
            host: self.host.trim().to_string(),
            port: self.port_str.trim().parse().unwrap_or(22),
            user: self.user.trim().to_string(),
            password: self.password.clone(),
        }
    }

    fn start_list(&mut self) {
        if self.host.trim().is_empty() || self.user.trim().is_empty() {
            self.status = "请先填写设备 IP 和用户名。".into();
            return;
        }
        self.persist();
        self.pending += 1;
        self.status = "正在连接设备并读取 SSID…".into();
        self.job_tx.send(Job::List(self.ssh_args())).ok();
    }

    fn start_rotate(&mut self) {
        let names: Vec<String> = self
            .selected
            .iter()
            .zip(self.vaps.iter())
            .filter_map(|(sel, name)| sel.then(|| name.clone()))
            .collect();
        if names.is_empty() {
            self.status = "没有勾选任何 SSID，请先勾选要修改的。".into();
            return;
        }
        self.persist();
        self.pending += 1;
        self.status = format!("正在保存 {} 个 SSID 的新密码…", names.len());
        self.job_tx
            .send(Job::Rotate {
                args: self.ssh_args(),
                names,
                pass: self.new_pass.clone(),
            })
            .ok();
    }

    fn start_snapshot(&mut self, label: &str, command: &str) {
        if self.host.trim().is_empty() || self.user.trim().is_empty() {
            self.status = "请先填写设备 IP 和用户名。".into();
            return;
        }
        self.persist();
        self.pending += 1;
        self.status = format!("正在执行「{label}」…");
        self.job_tx
            .send(Job::Snapshot {
                args: self.ssh_args(),
                label: label.to_string(),
                command: format!("{command}\n"),
            })
            .ok();
    }

    /// Drain all worker->UI channels into UI state (non-blocking).
    fn poll_results(&mut self) {
        // 1) 2FA code request
        if let Ok(guard) = self.prompt_rx.try_lock() {
            while guard.try_recv().is_ok() {
                self.need_code = true;
                self.code.clear();
                self.code_hint = "设备要求邮箱验证码。查看你的邮箱，把 6 位数字填进下面框里。".into();
            }
        }

        // 2) live transcript
        if let Ok(guard) = self.live_rx.try_lock() {
            let mut got = false;
            while let Ok(line) = guard.try_recv() {
                got = true;
                for piece in line.split('\n') {
                    if !piece.trim().is_empty() {
                        self.live_log.push_back(piece.to_string());
                    }
                }
                if self.live_log.len() > 40 {
                    self.live_log.drain(0..(self.live_log.len() - 40));
                }
            }
            let _ = got;
        }

        // 3) finished jobs
        while let Ok(out) = self.result_rx.try_recv() {
            self.pending = self.pending.saturating_sub(1);
            self.need_code = false;
            self.code.clear();
            match out {
                Ok(JobOutcome::List(vaps)) => {
                    self.vaps = vaps.clone();
                    self.selected = vec![true; vaps.len()];
                    self.status =
                        format!("找到 {} 个 SSID。填新密码后点「保存」。", vaps.len());
                }
                Ok(JobOutcome::Msg(m)) => {
                    self.status = m;
                    self.new_pass.clear();
                }
                Err(e) => {
                    self.status = format!("出错：{e}");
                }
            }
        }
    }

    /// Push the typed 2FA code to the worker and clear the prompt.
    fn submit_code(&mut self, ctx: &egui::Context) {
        let c = self.code.trim().to_string();
        if c.is_empty() {
            return;
        }
        if let Ok(guard) = self.code_tx.try_lock() {
            let _ = guard.send(c);
        }
        self.need_code = false;
        self.code.clear();
        self.status = "已提交验证码，设备校验中…".into();
        ctx.request_repaint();
    }
}

impl eframe::App for GuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_results();

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("FortiGate WiFi 密码管理");
            ui.separator();

            if self.pending > 0 {
                ui.colored_label(
                    egui::Color32::from_rgb(240, 180, 60),
                    "正在操作，请稍候…",
                );
            }

            // --- connection settings: one input per line, field fills remaining width ---
            ui.horizontal(|ui| {
                ui.label("设备 IP：");
                ui.add(egui::TextEdit::singleline(&mut self.host).desired_width(f32::INFINITY));
            });
            ui.horizontal(|ui| {
                ui.label("端口：");
                ui.add(egui::TextEdit::singleline(&mut self.port_str).desired_width(80.0));
            });
            ui.horizontal(|ui| {
                ui.label("用户名：");
                ui.add(egui::TextEdit::singleline(&mut self.user).desired_width(f32::INFINITY));
            });
            ui.horizontal(|ui| {
                ui.label("密码：");
                ui.add(egui::TextEdit::singleline(&mut self.password).password(true).desired_width(f32::INFINITY));
            });
            ui.horizontal(|ui| {
                let before = self.remember;
                let resp = ui.checkbox(
                    &mut self.remember,
                    "记住此设备（取消勾选将清除已保存的登录信息）",
                );
                if before && !self.remember && resp.changed() {
                    delete_config();
                }
            });

            // --- 2FA human-in-the-loop: pops in only when the device asks ---
            if self.need_code {
                ui.separator();
                ui.colored_label(
                    egui::Color32::from_rgb(255, 90, 90),
                    "⚠ 需要邮箱验证码",
                );
                ui.label(&self.code_hint);
                ui.horizontal(|ui| {
                    ui.label("验证码：");
                    // Bind DIRECTLY to self.code so typed digits survive the
                    // 200ms forced repaints (a local clone would be discarded
                    // each frame). egui mutates it in place.
                    let resp = ui.add(
                        egui::TextEdit::singleline(&mut self.code)
                            .font(egui::TextStyle::Monospace)
                            .desired_width(140.0),
                    );
                    let submit_btn = ui.button("填入");
                    if submit_btn.clicked() || resp.lost_focus() {
                        self.submit_code(ctx);
                    }
                    ui.label("填完点「填入」（点别处自动提交）");
                });
            }

            let busy = self.pending > 0;
            if ui
                .add_enabled(!busy, egui::Button::new("连接并读取 SSID"))
                .clicked()
            {
                self.start_list();
            }

            ui.separator();

            // --- live device transcript (read-only, sticks to bottom) ---
            if !self.live_log.is_empty() {
                ui.label("设备实时回显：");
                egui::ScrollArea::vertical()
                    .stick_to_bottom(true)
                    .auto_shrink([false, true])
                    .max_height(150.0)
                    .id_salt("device_log")
                    .show(ui, |ui| {
                        for line in self.live_log.iter() {
                            ui.monospace(line);
                        }
                    });
                ui.separator();
            }

            // --- VAP list ---
            if self.vaps.is_empty() {
                ui.label("（尚未读取 SSID 列表）");
            } else {
                ui.label("SSID 列表（勾选要修改的）：");
                ui.horizontal(|ui| {
                    if ui.button("全选").clicked() {
                        self.selected.fill(true);
                    }
                    if ui.button("全不选").clicked() {
                        self.selected.fill(false);
                    }
                });
                for (i, name) in self.vaps.iter().enumerate() {
                    let idx = i;
                    let sel = &mut self.selected[idx];
                    ui.horizontal(|ui| {
                        ui.checkbox(sel, name);
                    });
                }
            }

            ui.separator();

            // --- new passphrase + save ---
            ui.horizontal(|ui| {
                ui.label("新密码：");
                ui.add(egui::TextEdit::singleline(&mut self.new_pass).password(true));
            });
            ui.label("（8-63 个字符，WPA2 标准）");

            let can_save = !busy && !self.vaps.is_empty() && !self.new_pass.is_empty();
            if ui
                .add_enabled(can_save, egui::Button::new("保存所选 SSID 的新密码"))
                .clicked()
            {
                self.start_rotate();
            }

            ui.separator();

            // --- device status quick view (read-only diagnostics) ---
            ui.heading("设备状态速览");
            ui.horizontal(|ui| {
                if !busy {
                    if ui.button("在线 WiFi 用户").clicked() {
                        self.start_snapshot(
                            "wifi_users",
                            "diagnose wireless-controller wlac -d sta",
                        );
                    }
                    ui.separator();
                    if ui.button("AP 状态").clicked() {
                        self.start_snapshot(
                            "ap_status",
                            "get wireless-controller wtp-status",
                        );
                    }
                }
            });
            ui.label(
                egui::RichText::new("（两条均需设备有无线控制器角色；2FA 设备会自动弹验证码）")
                    .weak()
                    .small(),
            );

            ui.separator();
            ui.add(egui::Label::new(self.status.clone()).wrap());
        });

        // Redraw periodically while a job is in flight or a 2FA code is
        // outstanding, so the live log / status / code field stay fresh
        // without waiting for user interaction.
        if self.pending > 0 || self.need_code {
            ctx.request_repaint_after(std::time::Duration::from_millis(200));
        }
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("FortiGate WiFi 密码管理")
            .with_inner_size([480.0, 760.0]),
        ..Default::default()
    };
    eframe::run_native(
        "fogate-wifi-gui",
        options,
        Box::new(|cc: &eframe::CreationContext<'_>| Ok(Box::new(GuiApp::new(cc)))),
    )
}
