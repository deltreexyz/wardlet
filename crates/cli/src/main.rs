//! The `wardlet` command. Parsing lives here. Crypto lives in `wardlet-core`.

mod debug;
mod fido;

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, ExitCode};

use clap::{Parser, Subcommand};
use wardlet_core::Error;
use wardlet_core::master::Master;
use wardlet_core::ops::{self, FileAction};
use wardlet_core::keyring::{self, MemberInfo, default_dir};
use zeroize::Zeroize;

#[derive(Parser)]
#[command(
    name = "wardlet",
    version,
    about = "Your key is the lock. Encrypt files with the security key you already own.",
    after_help = "\
Examples:
  wardlet init               First run. Create the keyring and enroll a FIDO2 key
  wardlet config             Add or remove a key
  wardlet enc README.md      Lock a file in place (removes the original after verify)
  wardlet enc --keep note.md Keep the plaintext beside the locked file
  wardlet enc -r ~/secrets   Lock every file in a directory
  wardlet dec README.md.age  Decrypt a file
  wardlet edit notes.txt.age Edit a locked file in your editor, then encrypt it again
  wardlet new notes.txt      Create a locked file in your editor
  wardlet index              List locked files this machine has recorded
  wardlet export keyring.wardlet
  wardlet import keyring.wardlet"
)]
struct Cli {
    /// Keyring directory. Defaults to $XDG_CONFIG_HOME/wardlet/keyring.
    #[arg(long, global = true)]
    dir: Option<PathBuf>,

    /// Print each step. Does not print the master key, PINs, or recovery codes.
    #[arg(long, global = true)]
    debug: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create the keyring and enroll a FIDO2 key.
    Init,
    /// Add or remove a key.
    Config,
    /// Lock files or directories. Replaces the original after the ciphertext verifies.
    Enc {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Walk directories.
        #[arg(short, long)]
        recursive: bool,
        /// Write ciphertext under this directory instead of beside the source.
        #[arg(long)]
        output: Option<PathBuf>,
        /// Leave the plaintext beside the locked file.
        #[arg(long)]
        keep: bool,
        /// Write ciphertext to standard output. The ciphertext is not verified.
        #[arg(long)]
        stdout: bool,
        /// Replace an existing locked file.
        #[arg(long)]
        force: bool,
    },
    /// Decrypt files or directories.
    Dec {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Walk directories.
        #[arg(short, long)]
        recursive: bool,
        /// Write plaintext under this directory instead of beside the source.
        #[arg(long)]
        output: Option<PathBuf>,
        /// Replace an existing plaintext file.
        #[arg(long)]
        force: bool,
    },
    /// Decrypt a locked file, open it in your editor until you quit, then encrypt it again.
    Edit { file: PathBuf },
    /// Create a new locked file in your editor, then encrypt it.
    New { file: PathBuf },
    /// List locked files recorded on this machine.
    Index {
        /// Drop entries whose files are missing, then list what remains.
        #[arg(long)]
        prune: bool,
    },
    /// Show key-directory health without unlocking it.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// List enrolled members.
    Keys {
        #[arg(long)]
        json: bool,
    },
    /// Unlock with the recovery code. The code keeps working until it is replaced.
    Recover,
    /// Write the keyring to one file. Encrypted files and the recovery code stay where they are.
    Export { file: PathBuf },
    /// Create a keyring from an export. Refuses when a keyring is already there.
    Import { file: PathBuf },
    /// Print the version.
    Version,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("wardlet: {err}");
            err.into_exit_code()
        }
    }
}

fn run(cli: Cli) -> Result<(), Error> {
    debug::set(cli.debug);
    debug::log(&format!(
        "starting {}{}",
        command_name(&cli.command),
        cli.dir
            .as_ref()
            .map(|dir| format!(" --dir {}", dir.display()))
            .unwrap_or_default()
    ));
    match cli.command {
        Command::Version => {
            println!("wardlet {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Command::Init => init(cli.dir, true),
        Command::Config => configure(cli.dir),
        Command::Enc {
            paths,
            recursive,
            output,
            keep,
            stdout,
            force,
        } => encrypt(cli.dir, &paths, recursive, output, keep, stdout, force),
        Command::Dec {
            paths,
            recursive,
            output,
            force,
        } => decrypt(cli.dir, &paths, recursive, output, force),
        Command::Edit { file } => edit(cli.dir, &file),
        Command::New { file } => new_file(cli.dir, &file),
        Command::Index { prune } => index_cmd(cli.dir, prune),
        Command::Status { json } => status(cli.dir, json),
        Command::Keys { json } => keys(cli.dir, json),
        Command::Recover => recover(cli.dir),
        Command::Export { file } => export_cmd(cli.dir, &file),
        Command::Import { file } => import_cmd(cli.dir, &file),
    }
}

fn init(dir: Option<PathBuf>, show_banner: bool) -> Result<(), Error> {
    let dir = keyring_dir(dir)?;
    if dir.exists() {
        return Err(Error::KeyringExists);
    }
    debug::log(&format!("keyring directory {}", dir.display()));
    if show_banner {
        print_banner();
    }
    println!("Add the keys you want in this keyring. Wardlet will create it when you are done.");
    println!(
        "You can add or remove keys later. After that, update the keyring on every computer that uses it. An older copy cannot open files encrypted after the change."
    );
    println!();
    print_fido2_requirement();
    let label = prompt_key_name("Label for this key")?;

    debug::log("enrolling the first FIDO2 key");
    let mut enrolled = fido::enroll_hardware_member(&label)?;
    debug::log("writing the keyring and the recovery wrapper");
    let created = keyring::init_hardware_keyring(&dir, &label, &enrolled.hmac, &enrolled.params);
    let mut created = created?;
    print_recovery_code(&created.recovery_code);
    let saved = confirm_recovery_saved()?;
    created.recovery_code.zeroize();
    if !saved {
        let removed = std::fs::remove_dir_all(&created.dir);
        clear_screen();
        println!("The recovery code was not saved, and it will not be shown again.");
        println!("This keyring was removed. Run wardlet init to start over.");
        enrolled.hmac.zeroize();
        return removed.map_err(Error::io);
    }
    clear_screen();
    println!("Keyring created at {}", created.dir.display());
    println!("Recipient: {}", created.recipient);
    print_authorized_keys(&keyring::list_members_unlocked(
        &created.dir,
        &created.master,
    )?);
    let more = offer_more_hardware_keys(&created.dir, &created.master);
    enrolled.hmac.zeroize();
    more
}

fn offer_more_hardware_keys(dir: &std::path::Path, master: &Master) -> Result<(), Error> {
    loop {
        println!();
        if !prompt_yes("Add another FIDO2 key to the keyring?") {
            debug::log("finished adding keys");
            break;
        }
        debug::log("enrolling another FIDO2 key");
        let label = prompt_key_name("Label for the new key")?;
        let mut enrolled = fido::enroll_hardware_member(&label)?;
        let added = keyring::add_hardware_member_unlocked(
            dir,
            master,
            &label,
            &enrolled.hmac,
            &enrolled.params,
        );
        enrolled.hmac.zeroize();
        let added = added?;
        println!(
            "Added {} on {} ({})",
            added.label, enrolled.params.key_product, added.id
        );
        print_authorized_keys(&keyring::list_members_unlocked(dir, master)?);
    }
    if keyring::list_members(dir)?.len() < 2 {
        println!();
        println!(
            "Recommendation: Enroll at least 2 FIDO2 keys. A second key unlocks the keyring if the first is lost."
        );
        println!("The recovery code is the backup if every FIDO2 key is lost.");
    }
    println!();
    println!("Your keyring is ready.");
    println!("Next: wardlet enc <file>");
    Ok(())
}

struct Visit {
    scratch: PathBuf,
    master: Master,
    changed: bool,
}

fn configure(dir: Option<PathBuf>) -> Result<(), Error> {
    let dir = keyring_dir(dir)?;
    recover_interrupted_commit(&dir);
    if !dir.join("config.toml").is_file() {
        print_banner();
        println!("No keyring at {}", dir.display());
        if !prompt_yes("Create a Wardlet keyring?") {
            return Ok(());
        }
        return init(Some(dir), false);
    }

    print_banner();
    let mut visit = None;
    let result = configure_visit(&dir, &mut visit);
    if let Some(visit) = &visit
        && visit.scratch.exists()
    {
        let _ = std::fs::remove_dir_all(&visit.scratch);
    }
    result
}

fn configure_visit(dir: &std::path::Path, visit: &mut Option<Visit>) -> Result<(), Error> {
    loop {
        let count = keyring::list_members(visit_dir(dir, visit))?.len();
        let noun = if count == 1 { "key" } else { "keys" };
        println!("Keyring: {}", dir.display());
        println!("{count} {noun}.");
        println!(
            "Add or remove the keys you want in this visit. Wardlet saves the keyring once when you quit."
        );
        println!(
            "Then export the keyring and import it on every other computer. An older copy cannot open files encrypted after this change."
        );
        if keyring::recovery_replacement_due(visit_dir(dir, visit))? {
            println!("The recovery code has been used. Add a FIDO2 key to replace it.");
        }
        println!();
        println!("n) Add a key");
        println!("d) Remove a key");
        println!("v) View keys");
        println!("q) Quit");
        match prompt_line(">")?.trim() {
            "q" | "Q" => return finish_visit(dir, visit),
            "v" | "V" => view_keys(dir, visit)?,
            "n" | "N" => {
                ensure_visit(dir, visit)?;
                let visit = visit.as_mut().expect("visit was just opened");
                add_user(&visit.scratch, &visit.master)?;
                visit.changed = true;
            }
            "d" | "D" => {
                ensure_visit(dir, visit)?;
                let visit = visit.as_mut().expect("visit was just opened");
                if remove_user(&visit.scratch, &visit.master)? {
                    visit.changed = true;
                }
            }
            _ => println!("Choose n, d, v, or q."),
        }
        println!();
    }
}

fn view_keys(dir: &std::path::Path, visit: &mut Option<Visit>) -> Result<(), Error> {
    ensure_visit(dir, visit)?;
    let visit = visit.as_ref().expect("visit was just opened");
    debug::log("listing keys");
    print_authorized_keys(&keyring::list_members_unlocked(
        &visit.scratch,
        &visit.master,
    )?);
    Ok(())
}

fn visit_dir<'a>(dir: &'a std::path::Path, visit: &'a Option<Visit>) -> &'a std::path::Path {
    visit
        .as_ref()
        .map(|visit| visit.scratch.as_path())
        .unwrap_or(dir)
}

fn ensure_visit(dir: &std::path::Path, visit: &mut Option<Visit>) -> Result<(), Error> {
    if visit.is_some() {
        return Ok(());
    }
    println!("Unlock the keyring.");
    let master = unlock_for_visit(dir)?;
    if !keyring::is_latest_master(dir, &master)? {
        return Err(Error::Other(
            "This recovery code opens an older version of the keyring. Use the latest recovery code to add or remove a key.".into(),
        ));
    }
    let scratch = visit_scratch(dir);
    keyring::copy_keyring(dir, &scratch)?;
    *visit = Some(Visit {
        scratch,
        master,
        changed: false,
    });
    Ok(())
}

fn visit_scratch(dir: &std::path::Path) -> PathBuf {
    let mut bytes = [0u8; 4];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    let name: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    let parent = dir.parent().unwrap_or_else(|| std::path::Path::new("."));
    parent.join(format!(".wardlet-visit-{name}"))
}

fn finish_visit(dir: &std::path::Path, visit: &mut Option<Visit>) -> Result<(), Error> {
    let Some(visit) = visit.as_mut() else {
        return Ok(());
    };
    if !visit.changed {
        return Ok(());
    }
    println!(
        "This visit updates the keyring. Save the new recovery code. Wardlet will then ask you to export it to your other computers."
    );
    debug::log("creating the next keyring version");
    let mut display = keyring::rotate_keyring(&visit.scratch, &visit.master)?;
    print_recovery_code(&display);
    let saved = confirm_recovery_saved()?;
    display.zeroize();
    if !saved {
        let _ = std::fs::remove_dir_all(&visit.scratch);
        clear_screen();
        println!("The keyring was not changed.");
        return Ok(());
    }
    clear_screen();
    commit_visit(dir, &visit.scratch)?;
    println!("The keyring is updated.");
    println!(
        "Export it and import that file on every computer that uses it. An older copy cannot open files encrypted from now on."
    );
    println!(
        "The previous recovery code opens only files from before this change. Keep the new code. Send that new code with the export if someone else will add a key. It is not inside the export."
    );
    Ok(())
}

/// A commit renames the keyring aside, then the new keyring into place. If the
/// program died between those renames, put the previous keyring back.
fn recover_interrupted_commit(dir: &Path) {
    if dir.exists() {
        return;
    }
    let parent = dir.parent().unwrap_or_else(|| Path::new("."));
    let Ok(entries) = std::fs::read_dir(parent) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with(".wardlet-previous-") && entry.path().is_dir() {
            if std::fs::rename(entry.path(), dir).is_ok() {
                println!(
                    "An earlier keyring update was interrupted. The previous keyring was restored at {}.",
                    dir.display()
                );
            }
            return;
        }
    }
}

fn commit_visit(keyring: &std::path::Path, scratch: &std::path::Path) -> Result<(), Error> {
    let parent = keyring.parent().unwrap_or_else(|| std::path::Path::new("."));
    let mut bytes = [0u8; 4];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    let name: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    let holding = parent.join(format!(".wardlet-previous-{name}"));
    std::fs::rename(keyring, &holding).map_err(Error::io)?;
    if let Err(err) = std::fs::rename(scratch, keyring) {
        let _ = std::fs::rename(&holding, keyring);
        return Err(Error::io(err));
    }
    std::fs::remove_dir_all(holding).map_err(Error::io)
}

fn unlock_for_visit(dir: &std::path::Path) -> Result<Master, Error> {
    println!("f) FIDO2 key");
    println!("r) Recovery code");
    loop {
        match prompt_line(">")?.trim() {
            "f" | "F" => return fido::unlock_keyring_with_hardware(dir),
            "r" | "R" => {
                debug::log("unlocking the visit with the recovery code");
                let mut typed = prompt_recovery_code()?;
                let master = keyring::unlock_with_recovery_code(dir, &typed);
                typed.zeroize();
                return master;
            }
            _ => println!("Choose f or r."),
        }
    }
}

fn export_cmd(dir: Option<PathBuf>, file: &std::path::Path) -> Result<(), Error> {
    let dir = keyring_dir(dir)?;
    debug::log("exporting the keyring");
    keyring::export_keyring(&dir, file)?;
    println!("Wrote {}", file.display());
    println!(
        "This file is the keyring. The recovery code is not in it. Keep that code where you already stored it."
    );
    println!("Encrypted files are not in it. They stay where you put them.");
    println!("Copy this file to another machine and run wardlet import.");
    println!("That machine can then decrypt files encrypted with this keyring.");
    Ok(())
}

fn import_cmd(dir: Option<PathBuf>, file: &std::path::Path) -> Result<(), Error> {
    let dir = keyring_dir(dir)?;
    debug::log("importing a keyring");
    keyring::import_keyring(file, &dir)?;
    println!("Keyring imported at {}", dir.display());
    println!(
        "The same FIDO2 keys unlock this keyring. The recovery code still has to come from wherever it was saved."
    );
    Ok(())
}

fn keys(dir: Option<PathBuf>, json: bool) -> Result<(), Error> {
    let dir = keyring_dir(dir)?;
    let members = keyring::list_members(&dir)?;
    if json {
        println!("{}", members_json(&members));
    } else {
        let noun = if members.len() == 1 { "key" } else { "keys" };
        println!("{} {noun}.", members.len());
        for member in &members {
            let kind = if member.key_product.is_empty() {
                member.mechanism.as_str()
            } else {
                member.key_product.as_str()
            };
            let used = if member.last_used.is_empty() {
                "never"
            } else {
                member.last_used.as_str()
            };
            println!("{}  {kind}  last used {used}", member.id);
        }
        println!(
            "Names are sealed in the keyring. Run wardlet config and choose v) View keys to see them."
        );
    }
    Ok(())
}

fn add_user(dir: &std::path::Path, master: &Master) -> Result<(), Error> {
    debug::log("adding a key");
    println!("Keyring unlocked.");
    println!("Enroll the new key.");
    let label = prompt_key_name("Label for the new key")?;

    debug::log("enrolling the new FIDO2 key");
    let mut enrolled = fido::enroll_hardware_member(&label)?;
    debug::log("writing the new key wrapper");
    let added =
        keyring::add_hardware_member_unlocked(dir, master, &label, &enrolled.hmac, &enrolled.params);
    enrolled.hmac.zeroize();
    let added = added?;
    println!(
        "Added {} on {} ({})",
        added.label, enrolled.params.key_product, added.id
    );
    print_authorized_keys(&keyring::list_members_unlocked(dir, master)?);
    Ok(())
}

fn recover(dir: Option<PathBuf>) -> Result<(), Error> {
    let dir = keyring_dir(dir)?;
    print_banner();
    debug::log("unlocking with the recovery code");
    let mut typed = prompt_recovery_code()?;
    let master = keyring::unlock_with_recovery_code(&dir, &typed);
    typed.zeroize();
    drop(master?);
    println!("Keyring unlocked with the recovery code.");
    println!("This code still works, including any copy you made, until you replace it.");
    println!("Add a FIDO2 key from `wardlet config`. Wardlet will then show a new recovery code.");
    Ok(())
}

fn print_recovery_code(code: &str) {
    println!();
    print_warning_box(&[
        "WARNING",
        "",
        "Save this recovery code now. It will not be shown again.",
        "Wardlet does not keep a copy. If you do not save it now, it is gone.",
        "",
        "This is the only way back in if every FIDO2 key is lost.",
        "Store it in a password manager keyring or a secure note.",
        "Do not store it in a file on this computer.",
        "",
        code,
    ]);
    println!();
}

fn print_warning_box(lines: &[&str]) {
    use std::io::IsTerminal;
    let width = lines
        .iter()
        .map(|line| line.chars().count())
        .max()
        .unwrap_or(0);
    let rule = "═".repeat(width + 2);
    println!("╔{rule}╗");
    for line in lines {
        let pad = " ".repeat(width - line.chars().count());
        if *line == "WARNING" && io::stdout().is_terminal() {
            println!("║ \x1b[1m{line}\x1b[0m{pad} ║");
        } else {
            println!("║ {line}{pad} ║");
        }
    }
    println!("╚{rule}╝");
}

fn confirm_recovery_saved() -> Result<bool, Error> {
    Ok(prompt_yes(
        "Please confirm you have saved your recovery code",
    ))
}

fn prompt_recovery_code() -> Result<String, Error> {
    rpassword::prompt_password("Recovery code: ").map_err(Error::io)
}

fn clear_screen() {
    use std::io::IsTerminal;
    if !io::stdout().is_terminal() && !io::stderr().is_terminal() {
        return;
    }
    print!("\x1b[2J\x1b[3J\x1b[H");
    let _ = io::stdout().flush();
}

fn remove_user(dir: &std::path::Path, master: &Master) -> Result<bool, Error> {
    let members = keyring::list_members(dir)?;
    if members.len() <= 1 {
        println!("The last key cannot be removed.");
        println!(
            "Only one key is enrolled. Keep the recovery code, or enroll another key, so a lost key does not mean lost files."
        );
        return Ok(false);
    }
    debug::log("removing a key");
    println!("Keyring unlocked.");
    let members = keyring::list_members_unlocked(dir, master)?;
    print_authorized_keys(&members);
    println!();
    let label = prompt_key_name("Label of the key to remove")?;
    let Some(member) = members
        .iter()
        .find(|member| member.label == label || member.id == label)
    else {
        return Err(Error::UnknownMember(label));
    };
    let key = if member.key_product.is_empty() {
        member.mechanism.as_str()
    } else {
        member.key_product.as_str()
    };
    if !prompt_yes(&format!("Remove {} ({key})?", member.label)) {
        println!("Removal cancelled.");
        return Ok(false);
    }
    keyring::remove_member_unlocked(dir, master, &label)?;
    println!("Removed {}", member.label);
    if members.len() == 2 {
        println!(
            "One key remains. Keep the recovery code, or enroll another key, so a lost key does not mean lost files."
        );
    }
    Ok(true)
}

fn encrypt(
    dir: Option<PathBuf>,
    paths: &[PathBuf],
    recursive: bool,
    output: Option<PathBuf>,
    keep: bool,
    stdout: bool,
    force: bool,
) -> Result<(), Error> {
    debug::log("encrypting named paths");
    let dir = keyring_dir(dir)?;
    if !dir.join("config.toml").is_file() {
        return Err(Error::KeyringNotFound);
    }
    let suffix = file_suffix(&dir);
    let stamp = keyring_stamp(&dir)?;
    let version = stamp.version;
    // Replace is the default. --stdout never deletes; --keep leaves plaintext.
    let remove_source = !keep && !stdout;
    let request = ops::EncryptRequest {
        paths,
        recursive,
        output: output.as_deref(),
        // Delete after report/index so a refused delete still leaves a clear trail.
        remove_source: false,
        stdout,
        force,
        suffix: &suffix,
        stamp: Some(stamp),
        keyring_dir: Some(&dir),
    };
    ops::preflight_encrypt(&request)?;
    let master = unlock_existing(&dir)?;
    if !keyring::is_latest_master(&dir, &master)? {
        return Err(Error::Other(
            "This key opens an older version of this keyring. Import the newer keyring before encrypting.".into(),
        ));
    }
    let actions = ops::encrypt_paths(&master, &request)?;
    report_actions(&actions, "encrypted");
    record_locked(&dir, &master, version, &actions);
    if remove_source {
        ops::delete_sources(&actions)?;
        print_deleted(&actions);
    }
    Ok(())
}

fn index_cmd(dir: Option<PathBuf>, prune: bool) -> Result<(), Error> {
    debug::log("listing the sealed file index");
    let dir = keyring_dir(dir)?;
    if !dir.join("config.toml").is_file() {
        return Err(Error::KeyringNotFound);
    }
    let master = unlock_existing(&dir)?;
    let entries = if prune {
        let (kept, removed) = keyring::prune_index(&dir, &master)?;
        if removed > 0 {
            println!("Removed {removed} missing path(s).");
        }
        kept
    } else {
        keyring::load_index(&dir, &master)?
    };
    if entries.is_empty() {
        println!("No locked files recorded on this machine yet.");
        return Ok(());
    }
    for entry in &entries {
        println!(
            "{}  (keyring v{}, {})",
            entry.path, entry.version, entry.locked_at
        );
    }
    Ok(())
}

/// Best-effort: a failed index write must not undo a successful lock.
fn record_locked(dir: &Path, master: &Master, version: u32, actions: &[FileAction]) {
    let destinations: Vec<PathBuf> = actions
        .iter()
        .filter_map(|action| match action {
            FileAction::Wrote { destination, .. } => Some(destination.clone()),
            _ => None,
        })
        .collect();
    if destinations.is_empty() {
        return;
    }
    if let Err(err) = keyring::upsert_many(dir, master, &destinations, version) {
        eprintln!("wardlet: warning: could not update the file index: {err}");
    }
}

fn decrypt(
    dir: Option<PathBuf>,
    paths: &[PathBuf],
    recursive: bool,
    output: Option<PathBuf>,
    force: bool,
) -> Result<(), Error> {
    debug::log("decrypting named paths");
    let dir = keyring_dir(dir)?;
    if !dir.join("config.toml").is_file() {
        return Err(Error::KeyringNotFound);
    }
    let suffix = file_suffix(&dir);
    let request = ops::DecryptRequest {
        paths,
        recursive,
        output: output.as_deref(),
        force,
        suffix: &suffix,
    };
    ops::preflight_decrypt(&request)?;
    let master = unlock_existing(&dir)?;
    let stamp = keyring_stamp(&dir)?;
    let chain = keyring::masters_covering(&dir, master)?;
    let actions = ops::decrypt_keyring(&chain, &stamp.keyring_id, stamp.version, &request)?;
    report_actions(&actions, "decrypted");
    Ok(())
}

fn edit(dir: Option<PathBuf>, file: &Path) -> Result<(), Error> {
    debug::log("editing a locked file");
    let dir = keyring_dir(dir)?;
    let suffix = file_suffix(&dir);
    let ciphertext = resolve_edit_ciphertext(file, &suffix)?;
    let plain_name = plaintext_name(&ciphertext, &suffix)?;
    let natural_plain = path_parent(&ciphertext).join(&plain_name);
    if natural_plain.exists() {
        return Err(Error::Other(format!(
            "{} is already here. Encrypt it again with wardlet enc, or remove it before editing.",
            natural_plain.display()
        )));
    }
    let keyring = keyring_stamp(&dir)?;
    match ops::file_stamp(&ciphertext)? {
        None => {
            return Err(Error::Other(format!(
                "{} was not encrypted with a Wardlet keyring. Use wardlet dec and wardlet enc for this file.",
                ciphertext.display()
            )));
        }
        Some(stamp) if stamp.keyring_id != keyring.keyring_id => {
            return Err(Error::Other(format!(
                "{} belongs to a different keyring. Import that keyring, then edit again.",
                ciphertext.display()
            )));
        }
        Some(_) => {}
    }

    let before = file_fingerprint(&ciphertext);
    let master = unlock_latest(&dir)?;
    let chain = keyring::masters_covering(&dir, master)?;
    let work = editor_work_dir(&ciphertext)?;
    let plain = work.join(&plain_name);
    let decrypt_result = ops::decrypt_keyring(
        &chain,
        &keyring.keyring_id,
        keyring.version,
        &ops::DecryptRequest {
            paths: std::slice::from_ref(&ciphertext),
            recursive: false,
            output: Some(&work),
            force: true,
            suffix: &suffix,
        },
    );
    if let Err(err) = decrypt_result {
        let _ = std::fs::remove_dir_all(&work);
        return Err(err);
    }
    if !plain.is_file() {
        let _ = std::fs::remove_dir_all(&work);
        return Err(Error::Other(format!(
            "decrypt did not write {}",
            plain.display()
        )));
    }

    println!(
        "Opening {} in the editor. Quit the editor to encrypt again.",
        plain_name
    );
    finish_editor_encrypt(
        &dir,
        &chain[0],
        &ciphertext,
        &plain,
        &work,
        &suffix,
        "Updated",
        before,
    )
}

fn new_file(dir: Option<PathBuf>, file: &Path) -> Result<(), Error> {
    debug::log("creating a locked file");
    let dir = keyring_dir(dir)?;
    let suffix = file_suffix(&dir);
    let (ciphertext, plain_name) = resolve_new_paths(file, &suffix)?;
    let natural_plain = path_parent(&ciphertext).join(&plain_name);
    if natural_plain.exists() {
        return Err(Error::Other(format!(
            "{} already exists. Remove it, or use wardlet enc.",
            natural_plain.display()
        )));
    }
    if ciphertext.exists() {
        return Err(Error::Other(format!(
            "{} already exists. Use wardlet edit to change it.",
            ciphertext.display()
        )));
    }

    let master = unlock_latest(&dir)?;
    let work = editor_work_dir(&ciphertext)?;
    let plain = work.join(&plain_name);
    if let Err(err) = create_private_empty_file(&plain) {
        let _ = std::fs::remove_dir_all(&work);
        return Err(err);
    }

    println!(
        "Opening {} in the editor. Quit the editor to encrypt it.",
        plain_name
    );
    finish_editor_encrypt(
        &dir,
        &master,
        &ciphertext,
        &plain,
        &work,
        &suffix,
        "Created",
        None,
    )
}

fn unlock_latest(dir: &Path) -> Result<Master, Error> {
    let master = unlock_existing(dir)?;
    if !keyring::is_latest_master(dir, &master)? {
        return Err(Error::Other(
            "This key opens an older version of this keyring. Import the newer keyring before encrypting.".into(),
        ));
    }
    Ok(master)
}

#[allow(clippy::too_many_arguments)]
fn finish_editor_encrypt(
    dir: &Path,
    master: &Master,
    ciphertext: &Path,
    plain: &Path,
    work: &Path,
    suffix: &str,
    done: &str,
    guard: Option<(std::time::SystemTime, u64)>,
) -> Result<(), Error> {
    match run_editor(plain) {
        Ok(status) if status.success() => {}
        Ok(status) => {
            eprintln!(
                "The editor exited with {}. {} was not written. Plaintext left at {}.",
                status.code().unwrap_or(1),
                ciphertext.display(),
                plain.display()
            );
            return Err(Error::Other("editor failed".into()));
        }
        Err(err) => {
            eprintln!(
                "Could not start the editor. {} was not written. Plaintext left at {}.",
                ciphertext.display(),
                plain.display()
            );
            return Err(err);
        }
    }

    let changed = match guard {
        Some(before) => file_fingerprint(ciphertext) != Some(before),
        None => ciphertext.exists(),
    };
    if changed {
        eprintln!(
            "{} changed while the editor was open. It was not replaced. Plaintext left at {}.",
            ciphertext.display(),
            plain.display()
        );
        return Err(Error::Other("ciphertext changed during edit".into()));
    }

    let stamp = keyring_stamp(dir)?;
    let version = stamp.version;
    let encrypt_result = ops::encrypt_paths(
        master,
        &ops::EncryptRequest {
            paths: &[plain.to_path_buf()],
            recursive: false,
            output: Some(path_parent(ciphertext)),
            remove_source: true,
            stdout: false,
            force: true,
            suffix,
            stamp: Some(stamp),
            keyring_dir: Some(dir),
        },
    );
    match encrypt_result {
        Ok(actions) => {
            let _ = std::fs::remove_dir_all(work);
            println!("{done} {}", ciphertext.display());
            record_locked(dir, master, version, &actions);
            Ok(())
        }
        Err(err) => {
            eprintln!(
                "{} was not written. Plaintext left at {}.",
                ciphertext.display(),
                plain.display()
            );
            Err(err)
        }
    }
}

fn path_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn resolve_new_paths(file: &Path, suffix: &str) -> Result<(PathBuf, String), Error> {
    let name = file
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| Error::Other(format!("{} has no file name", file.display())))?;
    let (ciphertext, plain_name) = if name.ends_with(suffix) {
        let plain = name
            .strip_suffix(suffix)
            .filter(|plain| !plain.is_empty())
            .ok_or_else(|| {
                Error::Other(format!("cannot name the plaintext for {}", file.display()))
            })?;
        (file.to_path_buf(), plain.to_owned())
    } else {
        (
            file.with_file_name(format!("{name}{suffix}")),
            name.to_owned(),
        )
    };
    Ok((ciphertext, plain_name))
}

fn resolve_edit_ciphertext(file: &Path, suffix: &str) -> Result<PathBuf, Error> {
    if file.is_file() {
        let name = file
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| Error::Other(format!("{} has no file name", file.display())))?;
        if name.ends_with(suffix) {
            return Ok(file.to_path_buf());
        }
        let age = file.with_file_name(format!("{name}{suffix}"));
        if age.is_file() {
            return Ok(age);
        }
        return Err(Error::Other(format!(
            "{} is not a locked Wardlet file. Pass the .age file, or a name that has one beside it.",
            file.display()
        )));
    }
    let name = file
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| Error::Other(format!("{} has no file name", file.display())))?;
    if name.ends_with(suffix) {
        return Err(Error::Other(format!("{} not found", file.display())));
    }
    let age = file.with_file_name(format!("{name}{suffix}"));
    if age.is_file() {
        return Ok(age);
    }
    Err(Error::Other(format!("{} not found", file.display())))
}

fn plaintext_name(ciphertext: &Path, suffix: &str) -> Result<String, Error> {
    let name = ciphertext
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| Error::Other(format!("{} has no file name", ciphertext.display())))?;
    let plain = name
        .strip_suffix(suffix)
        .ok_or_else(|| Error::Other(format!("{} is not a {suffix} file", ciphertext.display())))?;
    if plain.is_empty() {
        return Err(Error::Other(format!(
            "cannot name the plaintext for {}",
            ciphertext.display()
        )));
    }
    Ok(plain.to_owned())
}

fn editor_work_dir(beside: &Path) -> Result<PathBuf, Error> {
    let mut bytes = [0u8; 4];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    let name: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR").filter(|value| !value.is_empty()) {
        candidates.push(PathBuf::from(runtime).join(format!("wardlet-edit-{name}")));
    }
    candidates.push(path_parent(beside).join(format!(".wardlet-edit-{name}")));
    candidates.push(std::env::temp_dir().join(format!("wardlet-edit-{name}")));
    let mut last_err = None;
    for candidate in candidates {
        match create_private_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(err) => last_err = Some(err),
        }
    }
    Err(last_err.unwrap_or_else(|| Error::Other("no editor work directory".into())))
}

fn file_fingerprint(path: &Path) -> Option<(std::time::SystemTime, u64)> {
    let meta = std::fs::metadata(path).ok()?;
    Some((meta.modified().ok()?, meta.len()))
}

fn create_private_dir(path: &Path) -> Result<(), Error> {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path).map_err(Error::io)
}

fn create_private_empty_file(path: &Path) -> Result<(), Error> {
    use std::fs::OpenOptions;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path).map_err(Error::io)?;
    file.sync_all().map_err(Error::io)
}

fn run_editor(path: &Path) -> Result<std::process::ExitStatus, Error> {
    if let Some(editor) = std::env::var_os("EDITOR").filter(|value| !value.is_empty()) {
        debug::log(&format!("running editor {}", editor.to_string_lossy()));
        match spawn_editor(&editor, path) {
            Ok(status) => return Ok(status),
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                println!(
                    "{} was not found. Falling back to nano, then vi. EDITOR is a program name only.",
                    editor.to_string_lossy()
                );
            }
            Err(err) => {
                return Err(Error::Other(format!(
                    "could not run {}: {err}",
                    editor.to_string_lossy()
                )));
            }
        }
    }
    debug::log("running editor nano");
    match spawn_editor(std::ffi::OsStr::new("nano"), path) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            debug::log("nano not available, falling back to vi");
            spawn_editor(std::ffi::OsStr::new("vi"), path)
                .map_err(|err| Error::Other(format!("could not run vi: {err}")))
        }
        other => other.map_err(|err| Error::Other(format!("could not run nano: {err}"))),
    }
}

fn spawn_editor(editor: &std::ffi::OsStr, path: &Path) -> io::Result<std::process::ExitStatus> {
    ProcessCommand::new(editor).arg(path).status()
}

fn keyring_stamp(dir: &std::path::Path) -> Result<ops::FileStamp, Error> {
    let text = std::fs::read_to_string(dir.join("config.toml")).map_err(Error::io)?;
    let config = keyring::load_config(&text)?;
    let version = keyring::keyring_version(&config);
    Ok(ops::FileStamp {
        keyring_id: config.keyring_id,
        version,
    })
}

fn wrote_sources(actions: &[FileAction]) -> Vec<&std::path::Path> {
    actions
        .iter()
        .filter_map(|action| match action {
            FileAction::Wrote { source, .. } => Some(source.as_path()),
            _ => None,
        })
        .collect()
}

fn print_deleted(actions: &[FileAction]) {
    let sources = wrote_sources(actions);
    if sources.is_empty() {
        return;
    }
    if sources.len() == 1 {
        println!("Deleted the original file {}.", sources[0].display());
        return;
    }
    println!("Deleted the original files.");
    for source in sources {
        println!("{}", source.display());
    }
}

fn file_suffix(dir: &std::path::Path) -> String {
    let Ok(text) = std::fs::read_to_string(dir.join("config.toml")) else {
        return ".age".into();
    };
    keyring::load_config(&text)
        .map(|config| config.settings.encryption_output_suffix)
        .unwrap_or_else(|_| ".age".into())
}

fn report_actions(actions: &[FileAction], verb: &str) {
    for action in actions {
        match action {
            FileAction::Wrote {
                source,
                destination,
                ..
            } => {
                println!("{verb} {} -> {}", source.display(), destination.display());
            }
            FileAction::Skipped { source } => {
                println!("skipped {}", source.display());
            }
            FileAction::ToStdout { source } => {
                eprintln!("{verb} {} -> stdout", source.display());
            }
        }
    }
}

fn unlock_existing(dir: &std::path::Path) -> Result<Master, Error> {
    if !keyring::has_hardware_member(dir)? {
        return Err(Error::Other("keyring has no FIDO2 key".into()));
    }
    debug::log("unlocking with a FIDO2 key");
    fido::unlock_keyring_with_hardware(dir)
}

fn status(dir: Option<PathBuf>, json: bool) -> Result<(), Error> {
    debug::log("reading keyring status");
    let dir = keyring_dir(dir)?;
    recover_interrupted_commit(&dir);
    let text = match std::fs::read_to_string(dir.join("config.toml")) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(Error::KeyringNotFound);
        }
        Err(err) => return Err(Error::io(err)),
    };
    let config = keyring::load_config(&text)?;
    let keys = config
        .keys
        .iter()
        .filter(|key| key.mechanism != keyring::RECOVERY_MECHANISM)
        .count();
    let recovery = config
        .keys
        .iter()
        .any(|key| key.mechanism == keyring::RECOVERY_MECHANISM);
    let version = keyring::keyring_version(&config);
    if json {
        println!(
            "{{\"keyring\":\"{}\",\"format_version\":{},\"version\":{version},\"keys\":{keys},\"recovery\":{recovery}}}",
            json_escape(&dir.display().to_string()),
            config.format_version,
        );
        return Ok(());
    }
    let noun = if keys == 1 { "key" } else { "keys" };
    println!("Keyring: {}", dir.display());
    println!("Format: {}", config.format_version);
    println!("Version: {version}");
    println!("Keys: {keys} {noun}");
    println!(
        "Recovery code: {}",
        if recovery { "enrolled" } else { "none" }
    );
    let mut problems = 0;
    let mut referenced: Vec<String> = config
        .keys
        .iter()
        .map(|key| {
            if key.mechanism == keyring::RECOVERY_MECHANISM {
                format!("keys/{}.age", key.id)
            } else {
                format!("keys/{}.mask", key.id)
            }
        })
        .collect();
    for generation in &config.generations {
        referenced.push(format!("epochs/{}.age", generation.epoch));
    }
    for relative in &referenced {
        if !dir.join(relative).is_file() {
            println!("Missing: {relative}");
            problems += 1;
        }
    }
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".partial") || name.starts_with(".wardlet-edit-") {
                println!("Leftover: {}", entry.path().display());
                problems += 1;
            }
        }
    }
    if let Some(parent) = dir.parent()
        && let Ok(entries) = std::fs::read_dir(parent)
    {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with(".wardlet-visit-") || name.starts_with(".wardlet-previous-") {
                println!("Leftover: {}", entry.path().display());
                problems += 1;
            }
        }
    }
    if problems == 0 {
        println!("Health: ok");
    } else {
        println!("Health: {problems} problem(s) above");
    }
    Ok(())
}

fn command_name(command: &Command) -> &'static str {
    match command {
        Command::Init => "init",
        Command::Config => "config",
        Command::Enc { .. } => "enc",
        Command::Dec { .. } => "dec",
        Command::Edit { .. } => "edit",
        Command::New { .. } => "new",
        Command::Index { .. } => "index",
        Command::Status { .. } => "status",
        Command::Keys { .. } => "keys",
        Command::Recover => "recover",
        Command::Export { .. } => "export",
        Command::Import { .. } => "import",
        Command::Version => "version",
    }
}

fn keyring_dir(dir: Option<PathBuf>) -> Result<PathBuf, Error> {
    match dir {
        Some(dir) => Ok(dir),
        None => default_dir(),
    }
}

fn print_fido2_requirement() {
    println!("Use a security key.");
    println!("Supported devices: https://wardlet.com/#devices");
    println!();
}

fn print_authorized_keys(members: &[MemberInfo]) {
    println!();
    println!("Authorized keys");
    print_members(members);
}

fn print_banner() {
    println!(
        "Wardlet {}\nYour key is the lock.\n",
        env!("CARGO_PKG_VERSION")
    );
}

fn print_members(members: &[MemberInfo]) {
    if members.is_empty() {
        println!("No keys.");
        return;
    }
    println!("Label\tKey\tLast used");
    for member in members {
        let key = if member.key_product.is_empty() {
            member.mechanism.as_str()
        } else {
            member.key_product.as_str()
        };
        let last_used = if member.last_used.is_empty() {
            "-"
        } else {
            member.last_used.as_str()
        };
        println!("{}\t{key}\t{last_used}", member.label);
    }
}

fn members_json(members: &[MemberInfo]) -> String {
    let mut json = String::from("[\n");
    for (index, member) in members.iter().enumerate() {
        json.push_str(&format!(
            "  {{\"id\":\"{}\",\"label\":\"{}\",\"mechanism\":\"{}\",\"key\":\"{}\",\"last_used\":\"{}\"}}",
            json_escape(&member.id),
            json_escape(&member.label),
            json_escape(&member.mechanism),
            json_escape(&member.key_product),
            json_escape(&member.last_used),
        ));
        if index + 1 != members.len() {
            json.push(',');
        }
        json.push('\n');
    }
    json.push(']');
    json
}

fn json_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn prompt_key_name(prompt: &str) -> Result<String, Error> {
    let label = prompt_line(prompt)?;
    let label = label.trim().to_owned();
    if label.is_empty() {
        return Err(Error::LabelRequired);
    }
    Ok(label)
}

fn prompt_yes(question: &str) -> bool {
    let line = prompt_line(&format!("{question} [y/N]")).unwrap_or_default();
    matches!(line.trim(), "y" | "Y" | "yes" | "YES")
}

fn prompt_line(prompt: &str) -> Result<String, Error> {
    eprint!("{prompt}: ");
    let _ = io::stderr().flush();
    let mut line = String::new();
    io::stdin().read_line(&mut line).map_err(Error::io)?;
    if line.is_empty() {
        return Err(Error::io("end of input"));
    }
    Ok(line)
}
