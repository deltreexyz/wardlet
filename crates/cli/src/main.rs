//! The `wardlet` command. Parsing lives here. Crypto lives in `wardlet-core`.

mod fido;

use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use wardlet_core::Error;
use wardlet_core::master::Master;
use wardlet_core::vault::{self, MemberInfo, default_dir};
use zeroize::Zeroize;

#[derive(Parser)]
#[command(
    name = "wardlet",
    version,
    about = "Encrypt and decrypt files with age"
)]
struct Cli {
    /// Key directory. Defaults to $XDG_CONFIG_HOME/wardlet/vault.
    #[arg(long, global = true)]
    dir: Option<PathBuf>,

    /// Enroll a passphrase user. A copied disk can be guessed offline.
    #[arg(long, global = true)]
    passphrase: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a key directory and its first user.
    Init,
    /// Create a vault, or add and remove users.
    Config,
    /// Encrypt files or directories.
    Enc {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Walk directories.
        #[arg(short, long)]
        recursive: bool,
        /// Write ciphertext under this directory instead of beside the source.
        #[arg(long)]
        output: Option<PathBuf>,
        /// Delete the plaintext after the ciphertext verifies.
        #[arg(long)]
        remove_source: bool,
        /// Write ciphertext to standard output.
        #[arg(long)]
        stdout: bool,
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
    match cli.command {
        Command::Version => {
            println!("wardlet {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Command::Init => init(cli.dir, cli.passphrase, true),
        Command::Config => configure(cli.dir, cli.passphrase),
        Command::Enc { .. } => Err(Error::Other("enc is not implemented yet".into())),
        Command::Dec { .. } => Err(Error::Other("dec is not implemented yet".into())),
        Command::Status { .. } => Err(Error::Other("status is not implemented yet".into())),
        Command::Keys { json } => keys(cli.dir, json),
        Command::Recover => recover(cli.dir),
    }
}

fn init(dir: Option<PathBuf>, passphrase: bool, show_banner: bool) -> Result<(), Error> {
    let dir = vault_dir(dir)?;
    if show_banner {
        print_banner();
    }
    if !passphrase {
        print_fido2_requirement();
    }
    let label = prompt_key_name("Label for this key")?;
    if passphrase {
        warn_passphrase_is_guessable();
        let mut typed = prompt_new_passphrase()?;
        eprintln!("Wrapping the master key. This takes about a second.");
        let created = vault::init_vault(&dir, &label, &typed);
        typed.zeroize();
        let mut created = created?;
        println!("Vault created at {}", created.dir.display());
        println!("Label: {label}");
        println!("Recipient: {}", created.recipient);
        println!("Losing this passphrase loses the files.");
        print_debug_banner(Some(&created.debug_master_secret), None);
        created.debug_master_secret.zeroize();
        return Ok(());
    }

    let mut enrolled = fido::enroll_hardware_member(&label)?;
    let created = vault::init_hardware_vault(&dir, &label, &enrolled.hmac, &enrolled.params);
    let mut created = created?;
    print_recovery_code(&created.recovery_code);
    let saved = confirm_recovery_saved()?;
    created.recovery_code.zeroize();
    if !saved {
        let removed = std::fs::remove_dir_all(&created.dir);
        clear_screen();
        println!("The recovery code was not saved, and it will not be shown again.");
        println!("This vault was removed. Run wardlet again to start over.");
        created.debug_master_secret.zeroize();
        enrolled.hmac.zeroize();
        return removed.map_err(Error::io);
    }
    clear_screen();
    println!("Vault created at {}", created.dir.display());
    println!("Recipient: {}", created.recipient);
    print_authorized_keys(&created.dir)?;
    let more = offer_more_hardware_keys(&created.dir, &created.debug_master_secret);
    print_debug_banner(Some(&created.debug_master_secret), Some(&enrolled.hmac));
    created.debug_master_secret.zeroize();
    enrolled.hmac.zeroize();
    more
}

fn offer_more_hardware_keys(dir: &std::path::Path, master_secret: &str) -> Result<(), Error> {
    let master = Master::from_bech32(master_secret)?;
    loop {
        println!();
        if !prompt_yes("Add another FIDO2 key to the vault?") {
            break;
        }
        let label = prompt_key_name("Label for the new key")?;
        let mut enrolled = fido::enroll_hardware_member(&label)?;
        let added = vault::add_hardware_member_unlocked(
            dir,
            &master,
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
        print_authorized_keys(dir)?;
    }
    if vault::list_members(dir)?.len() < 2 {
        println!();
        println!(
            "Recommendation: Enroll at least 2 FIDO2 keys. A second key unlocks the vault if the first is lost."
        );
        println!("The recovery code is the backup if every FIDO2 key is lost.");
    }
    Ok(())
}

fn configure(dir: Option<PathBuf>, passphrase: bool) -> Result<(), Error> {
    let dir = vault_dir(dir)?;
    if !dir.join("config.toml").is_file() {
        print_banner();
        println!("No vault at {}", dir.display());
        if !prompt_yes("Create a Wardlet vault?") {
            return Ok(());
        }
        return init(Some(dir), passphrase, false);
    }

    print_banner();
    loop {
        let members = vault::list_members(&dir)?;
        println!("Vault: {}", dir.display());
        if vault::recovery_replacement_due(&dir)? {
            println!("The recovery code has been used. Add a FIDO2 key to replace it.");
        }
        println!();
        println!("Authorized keys");
        print_members(&members);
        println!();
        println!("n) Add a key");
        println!("d) Remove a key");
        println!("q) Quit");
        match prompt_line(">")?.trim() {
            "q" | "Q" => return Ok(()),
            "n" | "N" => add_user(&dir, passphrase)?,
            "d" | "D" => remove_user(&dir, passphrase)?,
            _ => println!("Choose n, d, or q."),
        }
        println!();
    }
}

fn keys(dir: Option<PathBuf>, json: bool) -> Result<(), Error> {
    let dir = vault_dir(dir)?;
    let members = vault::list_members(&dir)?;
    if json {
        println!("{}", members_json(&members));
    } else {
        print_members(&members);
    }
    Ok(())
}

fn add_user(dir: &std::path::Path, passphrase: bool) -> Result<(), Error> {
    println!("Adding a key has two steps.");
    println!("1. Unlock the vault with a key that is already enrolled.");
    let master = unlock_existing(dir, passphrase)?;
    println!("Vault unlocked.");
    println!("2. Enroll the new key.");
    let label = prompt_key_name("Label for the new key")?;
    if passphrase {
        warn_passphrase_is_guessable();
        let mut new_passphrase = prompt_new_passphrase()?;
        eprintln!("Wrapping the master key. This takes about a second.");
        let added = vault::add_passphrase_member_unlocked(dir, &master, &label, &new_passphrase);
        new_passphrase.zeroize();
        let added = added?;
        println!("Added {} ({})", added.label, added.id);
        return Ok(());
    }

    let mut enrolled = fido::enroll_hardware_member(&label)?;
    let added =
        vault::add_hardware_member_unlocked(dir, &master, &label, &enrolled.hmac, &enrolled.params);
    enrolled.hmac.zeroize();
    let added = added?;
    println!(
        "Added {} on {} ({})",
        added.label, enrolled.params.key_product, added.id
    );
    print_authorized_keys(dir)?;
    if vault::recovery_replacement_due(dir)? {
        replace_recovery_code(dir, &master)?;
    }
    Ok(())
}

fn recover(dir: Option<PathBuf>) -> Result<(), Error> {
    let dir = vault_dir(dir)?;
    print_banner();
    let mut typed = prompt_line("Recovery code")?;
    let master = vault::unlock_with_recovery_code(&dir, &typed);
    typed.zeroize();
    drop(master?);
    println!("Vault unlocked with the recovery code.");
    println!("This code still works, including any copy you made, until you replace it.");
    println!("Add a FIDO2 key from `wardlet config`. Wardlet will then show a new recovery code.");
    Ok(())
}

fn replace_recovery_code(dir: &std::path::Path, master: &Master) -> Result<(), Error> {
    eprintln!("Wrapping a new recovery code. This takes about a second.");
    let (mut display, bytes) = vault::stage_recovery_wrapper(master)?;
    print_recovery_code(&display);
    let saved = confirm_recovery_saved()?;
    display.zeroize();
    clear_screen();
    if saved {
        vault::commit_recovery_wrapper(dir, &bytes)?;
        println!("The previous recovery code no longer unlocks this vault.");
    } else {
        println!("The new recovery code was not saved, so it was discarded.");
        println!("The previous recovery code still unlocks this vault.");
    }
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
        "Store it in a password manager vault or a secure note.",
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
    loop {
        let line = prompt_line("Please confirm you have saved your recovery code [Y/n]")?;
        match line.trim() {
            "" | "y" | "Y" | "yes" | "YES" => return Ok(true),
            "n" | "N" | "no" | "NO" => return Ok(false),
            _ => println!("Answer y or n."),
        }
    }
}

fn clear_screen() {
    use std::io::IsTerminal;
    if !io::stdout().is_terminal() && !io::stderr().is_terminal() {
        return;
    }
    print!("\x1b[2J\x1b[3J\x1b[H");
    let _ = io::stdout().flush();
}

fn remove_user(dir: &std::path::Path, passphrase: bool) -> Result<(), Error> {
    let members = vault::list_members(dir)?;
    if members.len() <= 1 {
        println!("The last key cannot be removed.");
        println!(
            "Only one key is enrolled. Keep the recovery code, or enroll another key, so a lost key does not mean lost files."
        );
        return Ok(());
    }
    println!("Unlock an enrolled key to authorize the removal.");
    let master = unlock_existing(dir, passphrase)?;
    println!("Vault unlocked.");
    println!();
    print_members(&members);
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
        return Ok(());
    }
    vault::remove_member_unlocked(dir, &master, &label)?;
    println!("Removed {}", member.label);
    if members.len() == 2 {
        println!(
            "One key remains. Keep the recovery code, or enroll another key, so a lost key does not mean lost files."
        );
    }
    Ok(())
}

fn unlock_existing(dir: &std::path::Path, passphrase: bool) -> Result<Master, Error> {
    let has_pass = vault::has_passphrase_member(dir)?;
    let has_hw = vault::has_hardware_member(dir)?;
    if has_hw && !(passphrase && has_pass) {
        return fido::unlock_vault_with_hardware(dir);
    }
    if has_pass {
        let mut typed = prompt_existing_passphrase()?;
        let master = vault::unlock_with_passphrase(dir, &typed);
        typed.zeroize();
        return master;
    }
    Err(Error::Other("vault has no users".into()))
}

fn warn_passphrase_is_guessable() {
    eprintln!("A copied disk can be guessed from this passphrase.");
}

fn print_debug_banner(master: Option<&str>, hmac: Option<&[u8; 32]>) {
    if std::env::var_os("WARDLET_DEBUG_SECRETS").is_none() {
        return;
    }
    println!("--- debug (build only; not printed in the product) ---");
    if let Some(master) = master {
        println!("master: {master}");
    }
    if let Some(hmac) = hmac {
        let hex: String = hmac.iter().map(|byte| format!("{byte:02x}")).collect();
        println!("hmac: {hex}");
    }
    println!("---");
}

fn vault_dir(dir: Option<PathBuf>) -> Result<PathBuf, Error> {
    match dir {
        Some(dir) => Ok(dir),
        None => default_dir(),
    }
}

fn print_fido2_requirement() {
    println!("Use a FIDO2-compatible key.");
    println!("Supported devices: https://wardlet.com/#devices");
    println!();
}

fn print_authorized_keys(dir: &std::path::Path) -> Result<(), Error> {
    println!();
    println!("Authorized keys");
    print_members(&vault::list_members(dir)?);
    Ok(())
}

fn print_banner() {
    println!(
        "Wardlet {}\nEncrypt files where they are. A FIDO2 key unlocks them.\n",
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

fn prompt_new_passphrase() -> Result<String, Error> {
    let mut first = rpassword::prompt_password("Passphrase: ").map_err(Error::io)?;
    let mut second = rpassword::prompt_password("Confirm passphrase: ").map_err(Error::io)?;
    let mismatch = first != second;
    let empty = first.is_empty();
    if mismatch || empty {
        first.zeroize();
        second.zeroize();
        return Err(if mismatch {
            Error::PassphraseMismatch
        } else {
            Error::PassphraseRequired
        });
    }
    second.zeroize();
    Ok(first)
}

fn prompt_existing_passphrase() -> Result<String, Error> {
    let passphrase =
        rpassword::prompt_password("Existing user's passphrase: ").map_err(Error::io)?;
    if passphrase.is_empty() {
        return Err(Error::PassphraseRequired);
    }
    Ok(passphrase)
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
