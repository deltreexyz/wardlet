//! Wardlet desktop front-end. Links `wardlet-core` (same vault and files as the CLI).

mod fido;
mod pin;
mod status_bus;

use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;

use eframe::egui;
use pin::PinBridge;
use status_bus::StatusBus;
use wardlet_core::ops::{DecryptRequest, EncryptRequest, decrypt_vault, encrypt_paths};
use wardlet_core::vault::{self, masters_covering};
use wardlet_core::Error;
use zeroize::Zeroize;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([520.0, 420.0])
            .with_min_inner_size([420.0, 320.0])
            .with_title("Wardlet"),
        ..Default::default()
    };
    eframe::run_native(
        "Wardlet",
        options,
        Box::new(|cc| Ok(Box::new(WardletApp::new(cc)))),
    )
}

enum Job {
    Init { label: String },
    Encrypt { path: PathBuf },
    Decrypt { path: PathBuf },
}

enum Event {
    Done(String),
    Failed(String),
    RecoveryCode(String),
}

struct WardletApp {
    vault_dir: PathBuf,
    status: StatusBus,
    pin: PinBridge,
    pin_draft: String,
    key_label: String,
    summary: String,
    recovery_once: Option<String>,
    busy: bool,
    jobs: Sender<Job>,
    events: Receiver<Event>,
}

impl WardletApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        apply_dark_theme(&cc.egui_ctx);
        let vault_dir = vault::default_dir().unwrap_or_else(|_| PathBuf::from("vault"));
        let status = StatusBus::default();
        let pin = PinBridge::new();
        let (job_tx, job_rx) = mpsc::channel();
        let (event_tx, event_rx) = mpsc::channel();
        let worker_status = status.clone();
        let worker_pin = pin.clone();
        let worker_dir = vault_dir.clone();
        thread::spawn(move || worker_loop(worker_dir, worker_pin, worker_status, job_rx, event_tx));
        let mut app = Self {
            vault_dir,
            status,
            pin,
            pin_draft: String::new(),
            key_label: "key".into(),
            summary: String::new(),
            recovery_once: None,
            busy: false,
            jobs: job_tx,
            events: event_rx,
        };
        app.refresh_summary();
        app
    }

    fn refresh_summary(&mut self) {
        self.summary = match read_vault_summary(&self.vault_dir) {
            Ok(text) => text,
            Err(Error::VaultNotFound) => format!(
                "No vault yet.\nPath: {}\nSet up with your keys to begin.",
                self.vault_dir.display()
            ),
            Err(err) => format!("Vault error: {err}"),
        };
    }

    fn start(&mut self, job: Job) {
        if self.busy {
            return;
        }
        self.busy = true;
        self.status.set("Working…");
        let _ = self.jobs.send(job);
    }
}

impl eframe::App for WardletApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        while let Ok(event) = self.events.try_recv() {
            self.busy = false;
            match event {
                Event::Done(message) => {
                    self.status.set(message);
                    self.refresh_summary();
                }
                Event::Failed(message) => {
                    self.status.set(message);
                    self.refresh_summary();
                }
                Event::RecoveryCode(code) => {
                    self.recovery_once = Some(code);
                    self.status
                        .set("Vault created. Store the recovery code, then dismiss.");
                    self.refresh_summary();
                }
            }
        }

        if self.pin.pending_prompt().is_some() || self.busy {
            ctx.request_repaint();
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Your key is the lock.");
            ui.label(
                egui::RichText::new("Hardware key file encryption")
                    .color(egui::Color32::from_rgb(125, 206, 168)),
            );
            ui.add_space(8.0);
            ui.monospace(self.summary.clone());
            ui.add_space(12.0);

            ui.horizontal(|ui| {
                ui.label("Key label");
                ui.text_edit_singleline(&mut self.key_label);
            });

            ui.horizontal(|ui| {
                if ui
                    .add_enabled(!self.busy, egui::Button::new("Set up vault"))
                    .clicked()
                {
                    let label = self.key_label.trim().to_owned();
                    if label.is_empty() {
                        self.status.set("Enter a label for the first key.");
                    } else {
                        self.start(Job::Init { label });
                    }
                }
                if ui
                    .add_enabled(!self.busy, egui::Button::new("Lock file"))
                    .clicked()
                    && let Some(path) = rfd::FileDialog::new().pick_file()
                {
                    self.start(Job::Encrypt { path });
                }
                if ui
                    .add_enabled(!self.busy, egui::Button::new("Open locked file"))
                    .clicked()
                    && let Some(path) = rfd::FileDialog::new()
                        .add_filter("Locked file", &["age"])
                        .pick_file()
                {
                    self.start(Job::Decrypt { path });
                }
                if ui.button("Refresh").clicked() {
                    self.refresh_summary();
                }
            });

            ui.add_space(10.0);
            ui.label(egui::RichText::new(self.status.get()).weak());

            if let Some(prompt) = self.pin.pending_prompt() {
                egui::Window::new("Security key PIN")
                    .collapsible(false)
                    .resizable(false)
                    .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                    .show(ctx, |ui| {
                        ui.label(prompt);
                        ui.add(
                            egui::TextEdit::singleline(&mut self.pin_draft)
                                .password(true)
                                .desired_width(220.0),
                        );
                        ui.horizontal(|ui| {
                            if ui.button("Unlock").clicked() {
                                let pin = std::mem::take(&mut self.pin_draft);
                                self.pin.submit(Some(pin));
                            }
                            if ui.button("Cancel").clicked() {
                                self.pin_draft.clear();
                                self.pin.cancel();
                            }
                        });
                    });
            }

            if let Some(code) = self.recovery_once.clone() {
                egui::Window::new("Recovery code — shown once")
                    .collapsible(false)
                    .resizable(false)
                    .anchor(egui::Align2::CENTER_CENTER, [0.0, 40.0])
                    .show(ctx, |ui| {
                        ui.label(
                            "Store this in a password manager. Wardlet keeps no copy. Changing keys later shows a new code.",
                        );
                        ui.add_space(6.0);
                        ui.monospace(&code);
                        ui.add_space(8.0);
                        if ui.button("I saved it").clicked() {
                            self.recovery_once = None;
                            self.status.set("Vault ready.");
                        }
                    });
            }
        });
    }
}

fn worker_loop(
    vault_dir: PathBuf,
    pin: PinBridge,
    status: StatusBus,
    jobs: Receiver<Job>,
    events: Sender<Event>,
) {
    while let Ok(job) = jobs.recv() {
        let result = match job {
            Job::Init { label } => run_init(&vault_dir, &label, &pin, &status),
            Job::Encrypt { path } => run_encrypt(&vault_dir, path, &pin, &status),
            Job::Decrypt { path } => run_decrypt(&vault_dir, path, &pin, &status),
        };
        let _ = events.send(match result {
            Ok(WorkerOk::Message(message)) => Event::Done(message),
            Ok(WorkerOk::Recovery(code)) => Event::RecoveryCode(code),
            Err(err) => Event::Failed(err.to_string()),
        });
    }
}

enum WorkerOk {
    Message(String),
    Recovery(String),
}

fn run_init(
    dir: &Path,
    label: &str,
    pin: &PinBridge,
    status: &StatusBus,
) -> Result<WorkerOk, Error> {
    if dir.exists() {
        return Err(Error::VaultExists);
    }
    let mut enrolled = fido::enroll_hardware_member(label, pin, status)?;
    let created = vault::init_hardware_vault(dir, label, &enrolled.hmac, &enrolled.params);
    enrolled.hmac.zeroize();
    let mut created = created?;
    let code = std::mem::take(&mut created.recovery_code);
    Ok(WorkerOk::Recovery(code))
}

fn run_encrypt(
    dir: &Path,
    path: PathBuf,
    pin: &PinBridge,
    status: &StatusBus,
) -> Result<WorkerOk, Error> {
    let master = fido::unlock_vault_with_hardware(dir, pin, status)?;
    if !vault::is_latest_master(dir, &master)? {
        return Err(Error::Other(
            "this key opens an older vault copy. Import the latest vault.".into(),
        ));
    }
    let text = std::fs::read_to_string(dir.join("config.toml")).map_err(Error::io)?;
    let config = vault::load_config(&text)?;
    let version = vault::vault_version(&config);
    let stamp = Some(wardlet_core::ops::FileStamp {
        vault_id: dir
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("vault")
            .to_owned(),
        version,
    });
    let request = EncryptRequest {
        paths: std::slice::from_ref(&path),
        recursive: false,
        output: None,
        remove_source: false,
        stdout: false,
        force: false,
        suffix: ".age",
        stamp,
    };
    wardlet_core::ops::preflight_encrypt(&request)?;
    let actions = encrypt_paths(&master, &request)?;
    let message = match actions.first() {
        Some(wardlet_core::ops::FileAction::Wrote { destination, .. }) => {
            format!("Locked copy: {}", destination.display())
        }
        _ => "Locked.".into(),
    };
    Ok(WorkerOk::Message(message))
}

fn run_decrypt(
    dir: &Path,
    path: PathBuf,
    pin: &PinBridge,
    status: &StatusBus,
) -> Result<WorkerOk, Error> {
    let master = fido::unlock_vault_with_hardware(dir, pin, status)?;
    let chain = masters_covering(dir, master)?;
    let text = std::fs::read_to_string(dir.join("config.toml")).map_err(Error::io)?;
    let config = vault::load_config(&text)?;
    let version = vault::vault_version(&config);
    let request = DecryptRequest {
        paths: std::slice::from_ref(&path),
        recursive: false,
        output: None,
        force: false,
        suffix: ".age",
    };
    wardlet_core::ops::preflight_decrypt(&request)?;
    decrypt_vault(&chain, "vault", version, &request)?;
    Ok(WorkerOk::Message(format!(
        "Opened beside the locked file: {}",
        path.display()
    )))
}

fn read_vault_summary(dir: &Path) -> Result<String, Error> {
    let text = match std::fs::read_to_string(dir.join("config.toml")) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(Error::VaultNotFound);
        }
        Err(err) => return Err(Error::io(err)),
    };
    let config = vault::load_config(&text)?;
    let keys = vault::list_members(dir)?.len();
    let version = vault::vault_version(&config);
    let noun = if keys == 1 { "key" } else { "keys" };
    Ok(format!(
        "Vault: {}\nVersion: {version}\nKeys: {keys} {noun}",
        dir.display()
    ))
}

fn apply_dark_theme(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = egui::Color32::from_rgb(16, 17, 15);
    visuals.window_fill = egui::Color32::from_rgb(24, 26, 23);
    visuals.override_text_color = Some(egui::Color32::from_rgb(244, 241, 234));
    ctx.set_visuals(visuals);
}
