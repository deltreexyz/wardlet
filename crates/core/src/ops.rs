//! Encrypt and decrypt the paths a person names.
//!
//! The vault does not keep a list of files. Ciphertext is an age file beside
//! the source, or under `--output`. The master stays in memory for this call.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use age::x25519::{Identity, Recipient};
use age::{Decryptor, Encryptor};
use age_core::format::{FileKey, Stanza};
use sha2::{Digest, Sha256};

use crate::Error;
use crate::master::Master;

const DEFAULT_SUFFIX: &str = ".age";
/// A file this large is checked by reading it twice, so the wait is visible.
const LARGE_FILE_BYTES: u64 = 100 * 1024 * 1024;

pub struct FileStamp {
    pub vault_id: String,
    pub version: u32,
}

pub struct EncryptRequest<'a> {
    pub paths: &'a [PathBuf],
    pub recursive: bool,
    pub output: Option<&'a Path>,
    pub remove_source: bool,
    pub stdout: bool,
    pub suffix: &'a str,
    pub stamp: Option<FileStamp>,
}

pub struct DecryptRequest<'a> {
    pub paths: &'a [PathBuf],
    pub recursive: bool,
    pub output: Option<&'a Path>,
    pub force: bool,
    pub suffix: &'a str,
}

#[derive(Debug)]
pub enum FileAction {
    Wrote {
        source: PathBuf,
        destination: PathBuf,
    },
    Skipped {
        source: PathBuf,
    },
    ToStdout {
        source: PathBuf,
    },
}

pub fn encrypt_paths(
    master: &Master,
    request: &EncryptRequest<'_>,
) -> Result<Vec<FileAction>, Error> {
    if request.stdout && request.remove_source {
        return Err(Error::Other(
            "--remove-source cannot be used with --stdout".into(),
        ));
    }
    let suffix = normalize_suffix(request.suffix);
    let jobs = collect(request.paths, request.recursive, &suffix, true)?;
    if request.stdout && jobs.iter().filter(|job| !job.skip).count() != 1 {
        return Err(Error::Other("--stdout encrypts exactly one file".into()));
    }
    let mut actions = Vec::new();
    for job in jobs {
        if job.skip {
            actions.push(FileAction::Skipped { source: job.source });
            continue;
        }
        if request.stdout {
            encrypt_to_stdout(master, &job.source, request.stamp.as_ref())?;
            actions.push(FileAction::ToStdout { source: job.source });
            continue;
        }
        let destination = destination_path(&job, &suffix, request.output, true)?;
        warn_if_newer_than_ciphertext(&job.source, &destination);
        encrypt_one(master, &job.source, &destination, request.stamp.as_ref())?;
        actions.push(FileAction::Wrote {
            source: job.source,
            destination,
        });
    }
    if request.remove_source {
        delete_sources(&actions)?;
    }
    Ok(actions)
}

/// Remove plaintext files after every ciphertext in this command has been verified.
pub fn delete_sources(actions: &[FileAction]) -> Result<(), Error> {
    for action in actions {
        if let FileAction::Wrote { source, .. } = action {
            fs::remove_file(source).map_err(Error::io)?;
        }
    }
    Ok(())
}

/// Check an encrypt command before any key is touched: paths exist and two
/// inputs never write the same destination.
pub fn preflight_encrypt(request: &EncryptRequest<'_>) -> Result<(), Error> {
    if request.stdout && request.remove_source {
        return Err(Error::Other(
            "--remove-source cannot be used with --stdout".into(),
        ));
    }
    let suffix = normalize_suffix(request.suffix);
    let jobs = collect(request.paths, request.recursive, &suffix, true)?;
    let mut destinations: HashSet<PathBuf> = HashSet::new();
    for job in jobs.iter().filter(|job| !job.skip) {
        if request.stdout {
            continue;
        }
        let destination = destination_path(job, &suffix, request.output, true)?;
        if !destinations.insert(destination.clone()) {
            return Err(Error::Other(format!(
                "two files would both be written to {}",
                destination.display()
            )));
        }
    }
    Ok(())
}

/// Check a decrypt command before any key is touched: paths exist, two inputs
/// never write the same destination, and no destination is already there.
pub fn preflight_decrypt(request: &DecryptRequest<'_>) -> Result<(), Error> {
    let suffix = normalize_suffix(request.suffix);
    let jobs = collect(request.paths, request.recursive, &suffix, false)?;
    let mut destinations: HashSet<PathBuf> = HashSet::new();
    for job in jobs.iter().filter(|job| !job.skip) {
        let destination = destination_path(job, &suffix, request.output, false)?;
        if !destinations.insert(destination.clone()) {
            return Err(Error::Other(format!(
                "two files would both be written to {}",
                destination.display()
            )));
        }
        if destination.exists() && !request.force {
            return Err(Error::Collision);
        }
    }
    Ok(())
}

pub fn decrypt_paths(
    master: &Master,
    request: &DecryptRequest<'_>,
) -> Result<Vec<FileAction>, Error> {
    decrypt_vault(std::slice::from_ref(master), "", 0, request)
}

pub fn decrypt_vault(
    masters: &[Master],
    vault_id: &str,
    version: u32,
    request: &DecryptRequest<'_>,
) -> Result<Vec<FileAction>, Error> {
    if masters.is_empty() {
        return Err(Error::Other("vault has no master".into()));
    }
    let suffix = normalize_suffix(request.suffix);
    let jobs = collect(request.paths, request.recursive, &suffix, false)?;
    let mut actions = Vec::new();
    for job in jobs {
        if job.skip {
            actions.push(FileAction::Skipped { source: job.source });
            continue;
        }
        let destination = destination_path(&job, &suffix, request.output, false)?;
        if destination.exists() && !request.force {
            return Err(Error::Collision);
        }
        decrypt_one(masters, vault_id, version, &job.source, &destination)?;
        actions.push(FileAction::Wrote {
            source: job.source,
            destination,
        });
    }
    Ok(actions)
}

fn warn_if_newer_than_ciphertext(source: &Path, destination: &Path) {
    let (Ok(source_meta), Ok(dest_meta)) = (fs::metadata(source), fs::metadata(destination)) else {
        return;
    };
    let (Ok(source_time), Ok(dest_time)) = (source_meta.modified(), dest_meta.modified()) else {
        return;
    };
    if source_time > dest_time {
        eprintln!(
            "Note: {} changed after it was encrypted. The new copy replaces {}.",
            source.display(),
            destination.display()
        );
    }
}

struct Job {
    source: PathBuf,
    /// Directory argument this file was found under, when the argument was a directory.
    root: Option<PathBuf>,
    skip: bool,
}

fn collect(
    paths: &[PathBuf],
    recursive: bool,
    suffix: &str,
    encrypting: bool,
) -> Result<Vec<Job>, Error> {
    let mut jobs = Vec::new();
    for path in paths {
        collect_one(path, path, recursive, suffix, encrypting, true, &mut jobs)?;
    }
    Ok(jobs)
}

fn collect_one(
    path: &Path,
    argument: &Path,
    recursive: bool,
    suffix: &str,
    encrypting: bool,
    is_argument: bool,
    jobs: &mut Vec<Job>,
) -> Result<(), Error> {
    let meta = fs::symlink_metadata(path).map_err(Error::io)?;
    if meta.file_type().is_symlink() {
        return Err(Error::Other(format!(
            "refusing to follow symlink {}",
            path.display()
        )));
    }
    if meta.is_dir() {
        if is_argument && !recursive {
            return Err(Error::Other(format!(
                "use -r to walk the directory {}",
                path.display()
            )));
        }
        let entries = fs::read_dir(path).map_err(Error::io)?;
        for entry in entries {
            let entry = entry.map_err(Error::io)?;
            collect_one(
                &entry.path(),
                argument,
                true,
                suffix,
                encrypting,
                false,
                jobs,
            )?;
        }
        return Ok(());
    }
    if !meta.is_file() {
        return Err(Error::Other(format!("{} is not a file", path.display())));
    }
    let name_is_ciphertext = file_name(path)?.ends_with(suffix);
    if encrypting && name_is_ciphertext {
        jobs.push(Job {
            source: path.to_path_buf(),
            root: None,
            skip: true,
        });
        return Ok(());
    }
    if !encrypting && !is_argument && !name_is_ciphertext {
        return Ok(());
    }
    let root = if argument.is_dir() {
        Some(argument.to_path_buf())
    } else {
        None
    };
    jobs.push(Job {
        source: path.to_path_buf(),
        root,
        skip: false,
    });
    Ok(())
}

fn destination_path(
    job: &Job,
    suffix: &str,
    output: Option<&Path>,
    encrypting: bool,
) -> Result<PathBuf, Error> {
    let name = file_name(&job.source)?;
    let output_name = if encrypting {
        format!("{name}{suffix}")
    } else if let Some(stripped) = name.strip_suffix(suffix) {
        stripped.to_owned()
    } else {
        format!("{name}.decrypted")
    };
    if output_name.is_empty() {
        return Err(Error::Other(format!(
            "cannot name the output for {}",
            job.source.display()
        )));
    }
    let relative = if let Some(root) = &job.root {
        job.source
            .strip_prefix(root)
            .unwrap_or(Path::new(&output_name))
    } else {
        Path::new(&output_name)
    };
    let mut relative = relative.to_path_buf();
    relative.set_file_name(&output_name);
    if let Some(output) = output {
        Ok(output.join(relative))
    } else {
        let parent = job
            .source
            .parent()
            .filter(|path| !path.as_os_str().is_empty());
        Ok(parent.unwrap_or_else(|| Path::new(".")).join(output_name))
    }
}

fn encrypt_one(
    master: &Master,
    source: &Path,
    destination: &Path,
    stamp: Option<&FileStamp>,
) -> Result<(), Error> {
    notice_if_large(source);
    if let Some(parent) = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(Error::io)?;
    }
    let partial = partial_path(destination);
    let write_result = (|| -> Result<Vec<u8>, Error> {
        let mut input = File::open(source).map_err(Error::io)?;
        let mut output = create_private_file(&partial)?;
        let plain_hash = encrypt_reader(master, &mut input, &mut output, stamp)?;
        output.sync_all().map_err(Error::io)?;
        Ok(plain_hash)
    })();
    let plain_hash = match write_result {
        Ok(hash) => hash,
        Err(err) => {
            let _ = fs::remove_file(&partial);
            return Err(err);
        }
    };
    let partial_file = File::open(&partial).map_err(Error::io)?;
    let opened_hash = decrypted_hash(master, partial_file)?;
    if opened_hash != plain_hash {
        let _ = fs::remove_file(&partial);
        return Err(Error::Other(format!(
            "ciphertext for {} did not match the plaintext",
            source.display()
        )));
    }
    if let Err(err) = replace_file(&partial, destination) {
        let _ = fs::remove_file(&partial);
        return Err(err);
    }
    Ok(())
}

fn encrypt_to_stdout(
    master: &Master,
    source: &Path,
    stamp: Option<&FileStamp>,
) -> Result<(), Error> {
    notice_if_large(source);
    let mut input = File::open(source).map_err(Error::io)?;
    let mut output = io::stdout().lock();
    encrypt_reader(master, &mut input, &mut output, stamp)?;
    Ok(())
}

fn encrypt_reader(
    master: &Master,
    input: &mut impl Read,
    output: &mut impl Write,
    stamp: Option<&FileStamp>,
) -> Result<Vec<u8>, Error> {
    let recipient = Recipient::from_str(&master.recipient())
        .map_err(|_| Error::InvalidConfig("master recipient does not parse".into()))?;
    let marker = stamp.map(StampRecipient::from_stamp);
    let mut recipients: Vec<&dyn age::Recipient> = vec![&recipient];
    if let Some(marker) = &marker {
        recipients.push(marker);
    }
    let encryptor = Encryptor::with_recipients(recipients.into_iter())
        .expect("wardlet and x25519 recipients share an empty label set");
    let mut writer = encryptor.wrap_output(output).map_err(Error::io)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let read = input.read(&mut buf).map_err(Error::io)?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
        writer.write_all(&buf[..read]).map_err(Error::io)?;
        buf[..read].fill(0);
    }
    writer.finish().map_err(Error::io)?;
    Ok(hasher.finalize().to_vec())
}

fn decrypt_one(
    masters: &[Master],
    vault_id: &str,
    version: u32,
    source: &Path,
    destination: &Path,
) -> Result<(), Error> {
    notice_if_large(source);
    if let Some(parent) = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(Error::io)?;
    }
    let partial = partial_path(destination);
    let write_result = (|| -> Result<(), Error> {
        for master in masters {
            let identity = Identity::from_str(master.expose_secret())
                .map_err(|_| Error::Other("vault master is not an age identity".into()))?;
            let input = File::open(source).map_err(Error::io)?;
            let decryptor = Decryptor::new(input)
                .map_err(|_| Error::Other(format!("{} is not an age file", source.display())))?;
            let mut reader =
                match decryptor.decrypt(std::iter::once(&identity as &dyn age::Identity)) {
                    Ok(reader) => reader,
                    Err(_) => continue,
                };
            let mut output = create_private_file(&partial)?;
            let mut buf = [0u8; 64 * 1024];
            loop {
                let read = reader.read(&mut buf).map_err(Error::io)?;
                if read == 0 {
                    break;
                }
                output.write_all(&buf[..read]).map_err(Error::io)?;
                buf[..read].fill(0);
            }
            output.sync_all().map_err(Error::io)?;
            return Ok(());
        }
        let header = read_header_prefix(source).unwrap_or_default();
        Err(Error::Other(stale_or_foreign(
            &header, vault_id, version, source,
        )))
    })();
    if let Err(err) = write_result {
        let _ = fs::remove_file(&partial);
        return Err(err);
    }
    replace_file(&partial, destination)
}

fn stale_or_foreign(ciphertext: &[u8], vault_id: &str, version: u32, path: &Path) -> String {
    if let Some(stamp) = read_stamp(ciphertext) {
        if !vault_id.is_empty() && stamp.vault_id == vault_id && stamp.version > version {
            return format!(
                "This file was encrypted with version {} of this vault. This copy is version {version}. Import the newer vault, then decrypt again.",
                stamp.version
            );
        }
    }
    format!("this vault cannot decrypt {}", path.display())
}

/// Vault id and version from a Wardlet age header, when present.
pub fn file_stamp(path: &Path) -> Result<Option<FileStamp>, Error> {
    let header = read_header_prefix(path)?;
    Ok(read_stamp(&header))
}

fn read_header_prefix(path: &Path) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    File::open(path)
        .map_err(Error::io)?
        .take(64 * 1024)
        .read_to_end(&mut buf)
        .map_err(Error::io)?;
    Ok(buf)
}

fn read_stamp(ciphertext: &[u8]) -> Option<FileStamp> {
    for line in ciphertext.split(|byte| *byte == b'\n').take(64) {
        let line = std::str::from_utf8(line).ok()?;
        if line == "---" {
            break;
        }
        let Some(rest) = line.strip_prefix("-> wardlet-v1 ") else {
            continue;
        };
        let mut parts = rest.split_whitespace();
        let vault_id = parts.next()?.to_owned();
        let version = parts.next()?.parse().ok()?;
        return Some(FileStamp { vault_id, version });
    }
    None
}

struct StampRecipient {
    vault_id: String,
    version: u32,
}

impl StampRecipient {
    fn from_stamp(stamp: &FileStamp) -> Self {
        Self {
            vault_id: stamp.vault_id.clone(),
            version: stamp.version,
        }
    }
}

impl age::Recipient for StampRecipient {
    fn wrap_file_key(
        &self,
        _file_key: &FileKey,
    ) -> Result<(Vec<Stanza>, HashSet<String>), age::EncryptError> {
        Ok((
            vec![Stanza {
                tag: "wardlet-v1".into(),
                args: vec![self.vault_id.clone(), self.version.to_string()],
                body: Vec::new(),
            }],
            HashSet::new(),
        ))
    }
}

fn decrypted_hash(master: &Master, input: impl Read) -> Result<Vec<u8>, Error> {
    let identity = Identity::from_str(master.expose_secret())
        .map_err(|_| Error::Other("vault master is not an age identity".into()))?;
    let decryptor =
        Decryptor::new(input).map_err(|_| Error::Other("ciphertext is not an age file".into()))?;
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|_| Error::Other("ciphertext does not open with this vault".into()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buf).map_err(Error::io)?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
        buf[..read].fill(0);
    }
    Ok(hasher.finalize().to_vec())
}

fn replace_file(partial: &Path, destination: &Path) -> Result<(), Error> {
    if let Err(err) = fs::rename(partial, destination) {
        let _ = fs::remove_file(partial);
        return Err(Error::io(err));
    }
    sync_parent(destination)
}

fn notice_if_large(path: &Path) {
    let Ok(meta) = fs::metadata(path) else {
        return;
    };
    let Some(message) = large_file_message(path, meta.len()) else {
        return;
    };
    eprintln!("{message}");
}

fn large_file_message(path: &Path, len: u64) -> Option<String> {
    if len < LARGE_FILE_BYTES {
        return None;
    }
    let mb = len.div_ceil(1024 * 1024);
    Some(format!(
        "{} is {mb} MB. Larger files take longer. Please be patient.",
        path.display()
    ))
}

fn sync_parent(path: &Path) -> Result<(), Error> {
    let Some(parent) = path.parent().filter(|path| !path.as_os_str().is_empty()) else {
        return Ok(());
    };
    let dir = File::open(parent).map_err(Error::io)?;
    dir.sync_all().map_err(Error::io)?;
    Ok(())
}

fn partial_path(destination: &Path) -> PathBuf {
    let name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("file");
    destination.with_file_name(format!(".{name}.partial"))
}

fn file_name(path: &Path) -> Result<String, Error> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .ok_or_else(|| Error::Other(format!("{} has no file name", path.display())))
}

fn normalize_suffix(suffix: &str) -> String {
    if suffix.is_empty() {
        DEFAULT_SUFFIX.to_owned()
    } else if suffix.starts_with('.') {
        suffix.to_owned()
    } else {
        format!(".{suffix}")
    }
}

fn create_private_file(path: &Path) -> Result<File, Error> {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(Error::Other(format!(
                "refusing to follow symlink {}",
                path.display()
            )));
        }
    }
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path).map_err(Error::io)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;

    use super::{
        DecryptRequest, EncryptRequest, FileAction, decrypt_paths, encrypt_paths,
        preflight_decrypt, preflight_encrypt,
    };
    use crate::master::Master;
    use crate::vault::keys::{identity_from_hmac, seal_mask};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let mut bytes = [0u8; 8];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
            let name: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
            let path = std::env::temp_dir().join(format!("wardlet-ops-{name}"));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn encrypt_file(
        master: &Master,
        path: &std::path::Path,
        remove_source: bool,
    ) -> Vec<FileAction> {
        encrypt_paths(
            master,
            &EncryptRequest {
                paths: &[path.to_path_buf()],
                recursive: false,
                output: None,
                remove_source,
                stdout: false,
                suffix: ".age",
                stamp: None,
            },
        )
        .unwrap()
    }

    #[test]
    fn preflight_refuses_colliding_batch_destinations() {
        let dir = TempDir::new();
        let a = dir.0.join("a");
        let b = dir.0.join("b");
        fs::create_dir_all(&a).unwrap();
        fs::create_dir_all(&b).unwrap();
        let one = a.join("same.txt");
        let two = b.join("same.txt");
        fs::write(&one, b"one").unwrap();
        fs::write(&two, b"two").unwrap();
        let out = dir.0.join("out");
        let paths = vec![one, two];
        let err = preflight_encrypt(&EncryptRequest {
            paths: &paths,
            recursive: false,
            output: Some(&out),
            remove_source: false,
            stdout: false,
            suffix: ".age",
            stamp: None,
        })
        .unwrap_err();
        assert!(err.to_string().contains("both be written"), "{err}");

        let existing = dir.0.join("plain.txt");
        fs::write(&existing, b"here").unwrap();
        let cipher = dir.0.join("plain.txt.age");
        fs::write(&cipher, b"x").unwrap();
        let err = preflight_decrypt(&DecryptRequest {
            paths: std::slice::from_ref(&cipher),
            recursive: false,
            output: None,
            force: false,
            suffix: ".age",
        })
        .unwrap_err();
        assert!(matches!(err, crate::Error::Collision), "{err}");
    }

    #[test]
    fn round_trip_and_a_second_encryption_differs() {
        let dir = TempDir::new();
        let source = dir.0.join("note.txt");
        fs::write(&source, b"keep this").unwrap();
        let master = Master::generate();
        let actions = encrypt_file(&master, &source, false);
        let FileAction::Wrote { destination, .. } = &actions[0] else {
            panic!("expected a write");
        };
        let first = fs::read(destination).unwrap();
        assert!(first.starts_with(b"age-encryption.org/v1\n"));
        assert!(source.is_file());

        let again = dir.0.join("note-2.txt");
        fs::write(&again, b"keep this").unwrap();
        let second_actions = encrypt_file(&master, &again, false);
        let FileAction::Wrote {
            destination: second,
            ..
        } = &second_actions[0]
        else {
            panic!("expected a write");
        };
        assert_ne!(first, fs::read(second).unwrap());

        let decrypted = decrypt_paths(
            &master,
            &DecryptRequest {
                paths: std::slice::from_ref(destination),
                recursive: false,
                output: Some(&dir.0.join("out")),
                force: false,
                suffix: ".age",
            },
        )
        .unwrap();
        let FileAction::Wrote {
            destination: plain, ..
        } = &decrypted[0]
        else {
            panic!("expected a write");
        };
        assert_eq!(fs::read(plain).unwrap(), b"keep this");
        assert_eq!(fs::read(&source).unwrap(), b"keep this");
    }

    #[test]
    fn a_second_wrap_of_the_master_decrypts_the_same_file() {
        let dir = TempDir::new();
        let source = dir.0.join("secret.txt");
        fs::write(&source, b"same master").unwrap();
        let master = Master::generate();
        let actions = encrypt_file(&master, &source, false);
        let FileAction::Wrote { destination, .. } = &actions[0] else {
            panic!("expected a write");
        };
        let before = fs::read(destination).unwrap();

        let hmac = [0x44u8; 32];
        let card = identity_from_hmac(&hmac).unwrap();
        let wrapped = seal_mask(&master, &card.recipient()).unwrap();
        let opened = crate::vault::keys::open_mask(&wrapped, &card).unwrap();
        assert_eq!(opened.recipient(), master.recipient());

        let out = dir.0.join("opened");
        decrypt_paths(
            &opened,
            &DecryptRequest {
                paths: std::slice::from_ref(destination),
                recursive: false,
                output: Some(&out),
                force: false,
                suffix: ".age",
            },
        )
        .unwrap();
        assert_eq!(fs::read(out.join("secret.txt")).unwrap(), b"same master");
        assert_eq!(fs::read(destination).unwrap(), before);
    }

    #[test]
    fn large_file_notice_starts_at_100_mb() {
        let path = std::path::Path::new("notes.txt");
        assert!(super::large_file_message(path, 100 * 1024 * 1024 - 1).is_none());
        let message = super::large_file_message(path, 100 * 1024 * 1024).unwrap();
        assert!(message.contains("notes.txt is 100 MB"));
        assert!(message.contains("Please be patient"));
    }

    #[test]
    fn encrypt_skips_age_files_and_refuses_symlinks() {
        let dir = TempDir::new();
        let age_file = dir.0.join("already.age");
        fs::write(&age_file, b"age-encryption.org/v1\n").unwrap();
        let master = Master::generate();
        let skipped = encrypt_file(&master, &age_file, false);
        assert!(matches!(skipped[0], FileAction::Skipped { .. }));

        let real = dir.0.join("real.txt");
        fs::write(&real, b"data").unwrap();
        let link = dir.0.join("link.txt");
        symlink(&real, &link).unwrap();
        let err = encrypt_paths(
            &master,
            &EncryptRequest {
                paths: &[link],
                recursive: false,
                output: None,
                remove_source: false,
                stdout: false,
                suffix: ".age",
                stamp: None,
            },
        )
        .unwrap_err();
        assert!(matches!(err, crate::Error::Other(_)));
        assert!(real.is_file());
    }

    #[test]
    fn encrypt_refuses_a_symlink_where_the_partial_would_be_written() {
        let dir = TempDir::new();
        let source = dir.0.join("note.txt");
        fs::write(&source, b"keep").unwrap();
        let outside = dir.0.join("outside.txt");
        fs::write(&outside, b"do not clobber").unwrap();
        let partial = dir.0.join(".note.txt.age.partial");
        symlink(&outside, &partial).unwrap();
        let master = Master::generate();
        let err = encrypt_paths(
            &master,
            &EncryptRequest {
                paths: &[source],
                recursive: false,
                output: None,
                remove_source: false,
                stdout: false,
                suffix: ".age",
                stamp: None,
            },
        )
        .unwrap_err();
        let message = err.to_string();
        assert!(message.contains("refusing to follow symlink"));
        assert_eq!(fs::read(&outside).unwrap(), b"do not clobber");
    }

    #[test]
    fn remove_source_keeps_the_plaintext_when_the_destination_cannot_be_written() {
        let dir = TempDir::new();
        let source = dir.0.join("keep.txt");
        fs::write(&source, b"still here").unwrap();
        let blocker = dir.0.join("blocked");
        fs::write(&blocker, b"not a directory").unwrap();
        let master = Master::generate();
        let err = encrypt_paths(
            &master,
            &EncryptRequest {
                paths: std::slice::from_ref(&source),
                recursive: false,
                output: Some(&blocker),
                remove_source: true,
                stdout: false,
                suffix: ".age",
                stamp: None,
            },
        )
        .unwrap_err();
        assert!(matches!(err, crate::Error::Io(_)));
        assert_eq!(fs::read(&source).unwrap(), b"still here");
    }

    #[test]
    fn remove_source_deletes_the_plaintext_after_the_ciphertext_verifies() {
        let dir = TempDir::new();
        let source = dir.0.join("gone.txt");
        fs::write(&source, b"verified").unwrap();
        let master = Master::generate();
        let actions = encrypt_file(&master, &source, true);
        let FileAction::Wrote { destination, .. } = &actions[0] else {
            panic!("expected a write");
        };
        assert!(!source.exists());
        let out = dir.0.join("back");
        decrypt_paths(
            &master,
            &DecryptRequest {
                paths: std::slice::from_ref(destination),
                recursive: false,
                output: Some(&out),
                force: false,
                suffix: ".age",
            },
        )
        .unwrap();
        assert_eq!(fs::read(out.join("gone.txt")).unwrap(), b"verified");
    }

    #[test]
    fn directory_walk_mirrors_files_and_requires_recursive() {
        let dir = TempDir::new();
        let nested = dir.0.join("secrets");
        fs::create_dir(&nested).unwrap();
        fs::write(nested.join("a.txt"), b"aaa").unwrap();
        let inner = nested.join("inner");
        fs::create_dir(&inner).unwrap();
        fs::write(inner.join("b.txt"), b"bbb").unwrap();
        fs::write(nested.join("skip.age"), b"nope").unwrap();
        let master = Master::generate();
        let err = encrypt_paths(
            &master,
            &EncryptRequest {
                paths: std::slice::from_ref(&nested),
                recursive: false,
                output: None,
                remove_source: false,
                stdout: false,
                suffix: ".age",
                stamp: None,
            },
        )
        .unwrap_err();
        assert!(matches!(err, crate::Error::Other(_)));

        let out = dir.0.join("cipher");
        encrypt_paths(
            &master,
            &EncryptRequest {
                paths: &[nested],
                recursive: true,
                output: Some(&out),
                remove_source: false,
                stdout: false,
                suffix: ".age",
                stamp: None,
            },
        )
        .unwrap();
        assert!(out.join("a.txt.age").is_file());
        assert!(out.join("inner").join("b.txt.age").is_file());
        assert!(!out.join("skip.age").exists());
        assert!(!out.join("skip.age.age").exists());
    }

    #[test]
    fn encrypting_again_replaces_the_ciphertext_after_it_verifies() {
        let dir = TempDir::new();
        let source = dir.0.join("note.txt");
        fs::write(&source, b"first").unwrap();
        let master = Master::generate();
        let actions = encrypt_file(&master, &source, false);
        let FileAction::Wrote { destination, .. } = &actions[0] else {
            panic!("expected a write");
        };
        let first = fs::read(destination).unwrap();
        fs::write(&source, b"second").unwrap();
        encrypt_file(&master, &source, false);
        let second = fs::read(destination).unwrap();
        assert_ne!(first, second);
        assert!(source.is_file());
        let out = dir.0.join("opened");
        decrypt_paths(
            &master,
            &DecryptRequest {
                paths: std::slice::from_ref(destination),
                recursive: false,
                output: Some(&out),
                force: false,
                suffix: ".age",
            },
        )
        .unwrap();
        assert_eq!(fs::read(out.join("note.txt")).unwrap(), b"second");
    }

    #[test]
    fn a_later_failure_does_not_delete_earlier_originals() {
        let dir = TempDir::new();
        let source = dir.0.join("keep.txt");
        fs::write(&source, b"still here").unwrap();
        let blocked = dir.0.join("blocked.txt");
        fs::write(&blocked, b"also here").unwrap();
        fs::create_dir(dir.0.join("blocked.txt.age")).unwrap();
        let master = Master::generate();
        let err = encrypt_paths(
            &master,
            &EncryptRequest {
                paths: &[source.clone(), blocked.clone()],
                recursive: false,
                output: None,
                remove_source: true,
                stdout: false,
                suffix: ".age",
                stamp: None,
            },
        )
        .unwrap_err();
        assert!(matches!(err, crate::Error::Io(_)));
        assert_eq!(fs::read(&source).unwrap(), b"still here");
        assert_eq!(fs::read(&blocked).unwrap(), b"also here");
        assert!(dir.0.join("keep.txt.age").is_file());
    }
}
