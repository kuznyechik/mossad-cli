use anyhow::{anyhow, bail, ensure, Context, Result};
use argon2::{Argon2, Params, Algorithm, Version};
use cipher::{NewCipher, StreamCipher};
use clap::{Parser, Subcommand};
use crc64fast::Digest;
use ctr::Ctr128BE;
use flate2::{read::DeflateDecoder, write::DeflateEncoder, Compression};
use hmac::{Hmac, Mac};
use indicatif::{ProgressBar, ProgressStyle};
use kuznyechik::Kuznyechik;
use rand::{rngs::OsRng, RngCore};
use rpassword::prompt_password;
use sha2::Sha256;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::{Duration, UNIX_EPOCH},
};
use walkdir::{DirEntry, WalkDir};
use zeroize::{Zeroize, ZeroizeOnDrop};

// Constants
const MAGIC: &[u8; 4] = b"MOSS";
const VERSION: u8 = 5;
const FLAG_COMPRESS: u8 = 0b0000_0001;

const MAX_FILES: u32 = 100_000;
const MAX_PATH_LEN: usize = 1024;
const MAX_FILE_SIZE: u64 = 16 * 1024 * 1024 * 1024; // 16 GB

const ARGON2_M_COST: u32 = 128 * 1024; // 128 MB
const ARGON2_T_COST: u32 = 4;
const ARGON2_P_COST: u32 = 1;

const BUFFER_SIZE: usize = 64 * 1024; // 64 KB

// CLI Definitions
#[derive(Parser)]
#[command(
    name = "mossad",
    version = "2.0",
    about = "Secure archive tool using Kuznyechik encryption"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create encrypted archive from directory
    Compress {
        /// Path to directory to archive
        #[arg(value_name = "DIR_PATH")]
        path: PathBuf,
        /// Output archive path (optional)
        #[arg(short, long, value_name = "ARCHIVE_PATH")]
        output: Option<PathBuf>,
    },
    /// Extract files from encrypted archive
    Extract {
        /// Archive file to extract
        #[arg(value_name = "ARCHIVE_PATH")]
        file: PathBuf,
        /// Output directory (optional)
        #[arg(short, long, value_name = "OUTPUT_DIR")]
        output: Option<PathBuf>,
    },
}

// Cryptographic Types
type HmacSha256 = Hmac<Sha256>;
type Aes256Ctr = Ctr128BE<Kuznyechik>;

// Archive Structures
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u8)]
enum FileType {
    Regular = 0,
    Symlink = 1,
}

#[derive(Debug)]
struct FileMetadata {
    path: PathBuf,
    original_size: u64,
    compressed_size: u64,
    crc64: u64,
    file_type: FileType,
    mode: u32,
    mtime: u64,
}

#[derive(Debug)]
struct ArchiveHeader {
    version: u8,
    flags: u8,
    nonce: [u8; 16],
    salt: [u8; 16],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
}

impl ArchiveHeader {
    fn new() -> Self {
        let mut nonce = [0u8; 16];
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut nonce);
        OsRng.fill_bytes(&mut salt);

        Self {
            version: VERSION,
            flags: FLAG_COMPRESS,
            nonce,
            salt,
            m_cost: ARGON2_M_COST,
            t_cost: ARGON2_T_COST,
            p_cost: ARGON2_P_COST,
        }
    }

    fn write(&self, writer: &mut impl Write) -> io::Result<()> {
        writer.write_all(MAGIC)?;
        writer.write_all(&[self.version, self.flags])?;
        writer.write_all(&(52u16.to_le_bytes()))?; // Header length
        writer.write_all(&self.nonce)?;
        writer.write_all(&self.salt)?;
        writer.write_all(&self.m_cost.to_le_bytes())?;
        writer.write_all(&self.t_cost.to_le_bytes())?;
        writer.write_all(&self.p_cost.to_le_bytes())?;
        Ok(())
    }

    fn read(reader: &mut impl Read) -> io::Result<Self> {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        if &magic != MAGIC {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid magic number"));
        }

        let mut version = [0u8; 1];
        reader.read_exact(&mut version)?;
        if version[0] != VERSION {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Unsupported version"));
        }

        let mut flags = [0u8; 1];
        reader.read_exact(&mut flags)?;

        let mut header_len = [0u8; 2];
        reader.read_exact(&mut header_len)?;
        let header_len = u16::from_le_bytes(header_len);
        if header_len != 52 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid header length"));
        }

        let mut nonce = [0u8; 16];
        reader.read_exact(&mut nonce)?;

        let mut salt = [0u8; 16];
        reader.read_exact(&mut salt)?;

        let mut m_cost = [0u8; 4];
        reader.read_exact(&mut m_cost)?;
        let m_cost = u32::from_le_bytes(m_cost);

        let mut t_cost = [0u8; 4];
        reader.read_exact(&mut t_cost)?;
        let t_cost = u32::from_le_bytes(t_cost);

        let mut p_cost = [0u8; 4];
        reader.read_exact(&mut p_cost)?;
        let p_cost = u32::from_le_bytes(p_cost);

        Ok(Self {
            version: version[0],
            flags: flags[0],
            nonce,
            salt,
            m_cost,
            t_cost,
            p_cost,
        })
    }
}

// Core Cryptography
#[derive(ZeroizeOnDrop)]
struct Keys {
    enc_key: Box<[u8; 32]>,
    mac_key: Box<[u8; 32]>,
}

impl Keys {
    fn derive(password: &mut String, salt: &[u8], params: Params) -> Result<Self> {
        let mut key_material = [0u8; 64];
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        
        argon2
            .hash_password_into(password.as_bytes(), salt, &mut key_material)
            .map_err(|e| anyhow!("Key derivation failed: {}", e))?;
        
        password.zeroize();
        
        let enc_key = Box::new(key_material[..32].try_into().unwrap());
        let mac_key = Box::new(key_material[32..].try_into().unwrap());
        key_material.zeroize();
        
        Ok(Self { enc_key, mac_key })
    }
}

// Platform-specific utilities
#[cfg(unix)]
fn get_file_mode(metadata: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    metadata.mode()
}

#[cfg(windows)]
fn get_file_mode(_meta: &std::fs::Metadata) -> u32 {
    0o644 // Default permissions for Windows
}

#[cfg(unix)]
fn set_file_permissions(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(windows)]
fn set_file_permissions(_path: &Path, _mode: u32) -> Result<()> {
    // No-op on Windows
    Ok(())
}

#[cfg(unix)]
fn create_symlink(original: &Path, link: &Path) -> Result<()> {
    std::os::unix::fs::symlink(original, link)?;
    Ok(())
}

#[cfg(windows)]
fn create_symlink(original: &Path, link: &Path) -> Result<()> {
    if original.is_dir() {
        std::os::windows::fs::symlink_dir(original, link)?;
    } else {
        std::os::windows::fs::symlink_file(original, link)?;
    }
    Ok(())
}

// Archive Processing
fn collect_files(root: &Path) -> Result<Vec<DirEntry>> {
    let mut files = Vec::new();
    let mut count = 0;

    for entry in WalkDir::new(root).follow_links(false) {
        let entry = entry.context("Failed to read directory")?;
        if entry.file_type().is_file() || entry.file_type().is_symlink() {
            count += 1;
            ensure!(count <= MAX_FILES, "Too many files (max: {})", MAX_FILES);
            files.push(entry);
        }
    }

    Ok(files)
}

fn process_file(entry: &DirEntry, root: &Path) -> Result<FileMetadata> {
    let path = entry.path().strip_prefix(root)
        .context("Invalid path prefix")?
        .to_path_buf();

    ensure!(
        path.as_os_str().len() <= MAX_PATH_LEN,
        "Path too long: {}",
        path.display()
    );

    let metadata = entry.metadata().context("Failed to read metadata")?;
    
    let mtime = match metadata.modified() {
        Ok(time) => time.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
        Err(_) => 0,
    };

    let mode = get_file_mode(&metadata);

    let file_type = if metadata.file_type().is_symlink() {
        FileType::Symlink
    } else {
        FileType::Regular
    };

    let original_size = if file_type == FileType::Symlink {
        fs::read_link(entry.path())
            .context("Failed to read symlink")?
            .as_os_str()
            .len() as u64
    } else {
        metadata.len()
    };

    ensure!(
        original_size <= MAX_FILE_SIZE,
        "File too large: {} (max: {} GB)",
        entry.path().display(),
        MAX_FILE_SIZE >> 30
    );

    Ok(FileMetadata {
        path,
        original_size,
        compressed_size: 0,
        crc64: 0,
        file_type,
        mode,
        mtime,
    })
}

fn create_archive(
    input_dir: &Path,
    output_path: &Path,
    password: &mut String,
) -> Result<()> {
    // Collect and validate files
    let entries = collect_files(input_dir)?;
    let mut metadata_list: Vec<FileMetadata> = entries
        .iter()
        .map(|e| process_file(e, input_dir))
        .collect::<Result<_>>()?;

    // Setup cryptographic components
    let header = ArchiveHeader::new();
    let params = Params::new(
        header.m_cost,
        header.t_cost,
        header.p_cost,
        Some(64),
    ).map_err(|e| anyhow!("Invalid Argon2 parameters: {}", e))?;

    let keys = Keys::derive(password, &header.salt, params)?;

    // Initialize encryption and MAC
    let mut cipher = Aes256Ctr::new((&*keys.enc_key).into(), (&header.nonce).into());
    let mut mac = HmacSha256::new_from_slice(&keys.mac_key[..])
        .map_err(|_| anyhow!("HMAC initialization failed"))?;

    // Create output file
    let mut output_file = BufWriter::with_capacity(
        BUFFER_SIZE,
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(output_path)
            .context("Failed to create archive")?,
    );

    // Write header
    header.write(&mut output_file)?;
    mac.update(MAGIC);
    mac.update(&[header.version, header.flags]);
    mac.update(&52u16.to_le_bytes());
    mac.update(&header.nonce);
    mac.update(&header.salt);
    mac.update(&header.m_cost.to_le_bytes());
    mac.update(&header.t_cost.to_le_bytes());
    mac.update(&header.p_cost.to_le_bytes());

    // Setup payload buffer
    let mut payload_writer = Vec::new();
    payload_writer.write_all(&(metadata_list.len() as u32).to_le_bytes())?;

    // Process files with progress bar
    let pb = ProgressBar::new(metadata_list.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}",
            )?
            .progress_chars("#>-"),
    );

    for (i, metadata) in metadata_list.iter_mut().enumerate() {
        pb.set_message(metadata.path.display().to_string());

        // Handle symlinks
        if metadata.file_type == FileType::Symlink {
            let target = fs::read_link(&entries[i].path())
                .context("Failed to read symlink target")?;
            let target_str = target.to_string_lossy().into_owned();
            metadata.original_size = target_str.len() as u64;
            
            let mut crc = Digest::new();
            crc.write(target_str.as_bytes());
            metadata.crc64 = crc.sum64();
            
            payload_writer.write_all(&(metadata.path.as_os_str().len() as u16).to_le_bytes())?;
            payload_writer.write_all(metadata.path.as_os_str().as_encoded_bytes())?;
            payload_writer.write_all(&metadata.original_size.to_le_bytes())?;
            payload_writer.write_all(&0u64.to_le_bytes())?; // Compressed size (0 for symlinks)
            payload_writer.write_all(&metadata.crc64.to_le_bytes())?;
            payload_writer.write_all(&(metadata.file_type as u8).to_le_bytes())?;
            payload_writer.write_all(&metadata.mode.to_le_bytes())?;
            payload_writer.write_all(&metadata.mtime.to_le_bytes())?;
            payload_writer.write_all(target_str.as_bytes())?;
            
            pb.inc(1);
            continue;
        }

        // Process regular files
        let mut buffer = vec![0u8; BUFFER_SIZE];
        let mut crc = Digest::new();
        let mut compressor = DeflateEncoder::new(Vec::new(), Compression::default());
        let mut file = BufReader::with_capacity(
            BUFFER_SIZE,
            File::open(&entries[i].path()).context("Failed to open file")?,
        );

        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            let current = &buffer[..bytes_read];
            crc.write(current);
            compressor.write_all(current)?;
        }

        let compressed = compressor.finish()?;
        metadata.compressed_size = compressed.len() as u64;
        metadata.crc64 = crc.sum64();

        // Write metadata
        payload_writer.write_all(&(metadata.path.as_os_str().len() as u16).to_le_bytes())?;
        payload_writer.write_all(metadata.path.as_os_str().as_encoded_bytes())?;
        payload_writer.write_all(&metadata.original_size.to_le_bytes())?;
        payload_writer.write_all(&metadata.compressed_size.to_le_bytes())?;
        payload_writer.write_all(&metadata.crc64.to_le_bytes())?;
        payload_writer.write_all(&(metadata.file_type as u8).to_le_bytes())?;
        payload_writer.write_all(&metadata.mode.to_le_bytes())?;
        payload_writer.write_all(&metadata.mtime.to_le_bytes())?;
        payload_writer.write_all(&compressed)?;

        pb.inc(1);
    }
    pb.finish_with_message("Encrypting payload");

    // Encrypt payload
    let mut encrypted_payload = payload_writer;
    cipher.apply_keystream(&mut encrypted_payload);
    let payload_size = encrypted_payload.len() as u64;

    // Update MAC with encrypted payload
    mac.update(&encrypted_payload);

    // Write payload and footer
    output_file.write_all(&encrypted_payload)?;
    output_file.write_all(&payload_size.to_le_bytes())?;
    mac.update(&payload_size.to_le_bytes());
    
    let tag = mac.finalize().into_bytes();
    output_file.write_all(&tag)?;
    output_file.flush()?;

    Ok(())
}

fn extract_archive(
    archive_path: &Path,
    output_dir: &Path,
    password: &mut String,
) -> Result<()> {
    let file_size = archive_path.metadata()?.len();
    ensure!(file_size > 92, "File too small to be valid archive");

    let mut file = BufReader::with_capacity(
        BUFFER_SIZE,
        File::open(archive_path).context("Failed to open archive")?,
    );

    // Read header
    let header = ArchiveHeader::read(&mut file)?;
    let params = Params::new(header.m_cost, header.t_cost, header.p_cost, Some(64))
        .map_err(|e| anyhow!("Invalid Argon2 parameters: {}", e))?;
    
    let keys = Keys::derive(password, &header.salt, params)?;

    // Read payload size and HMAC tag
    file.seek(SeekFrom::End(-40))?; // 8 (size) + 32 (tag)
    let mut footer = [0u8; 40];
    file.read_exact(&mut footer)?;
    
    let payload_size = u64::from_le_bytes(footer[..8].try_into()?);
    let stored_tag = &footer[8..];

    // Read ciphertext
    let ciphertext_pos = 52; // Header length
    let ciphertext_len = payload_size as usize;
    ensure!(
        ciphertext_pos as u64 + payload_size + 40 <= file_size,
        "Corrupted archive structure"
    );

    file.seek(SeekFrom::Start(ciphertext_pos as u64))?;
    let mut ciphertext = vec![0u8; ciphertext_len];
    file.read_exact(&mut ciphertext)?;

    // Verify HMAC
    let mut mac = HmacSha256::new_from_slice(&keys.mac_key[..])?;
    mac.update(MAGIC);
    mac.update(&[header.version, header.flags]);
    mac.update(&52u16.to_le_bytes());
    mac.update(&header.nonce);
    mac.update(&header.salt);
    mac.update(&header.m_cost.to_le_bytes());
    mac.update(&header.t_cost.to_le_bytes());
    mac.update(&header.p_cost.to_le_bytes());
    mac.update(&ciphertext);
    mac.update(&payload_size.to_le_bytes());

    mac.verify_slice(stored_tag)
        .context("Invalid password or corrupted archive")?;

    // Decrypt payload
    let mut cipher = Aes256Ctr::new((&*keys.enc_key).into(), (&header.nonce).into());
    let mut payload = ciphertext;
    cipher.apply_keystream(&mut payload);

    // Process payload
    let mut cursor = io::Cursor::new(payload);
    let mut buf = [0u8; 4];
    cursor.read_exact(&mut buf)?;
    let file_count = u32::from_le_bytes(buf);
    ensure!(file_count > 0, "Empty archive");
    ensure!(file_count <= MAX_FILES, "Too many files in archive");

    let pb = ProgressBar::new(file_count as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}",
            )?
            .progress_chars("#>-"),
    );

    for _ in 0..file_count {
        // Read path
        let mut buf = [0u8; 2];
        cursor.read_exact(&mut buf)?;
        let path_len = u16::from_le_bytes(buf) as usize;
        ensure!(path_len > 0 && path_len <= MAX_PATH_LEN, "Invalid path length");
        
        let mut path_bytes = vec![0u8; path_len];
        cursor.read_exact(&mut path_bytes)?;
        let path = PathBuf::from(String::from_utf8(path_bytes)?);
        let full_path = output_dir.join(path);

        // Read metadata
        let mut buf = [0u8; 8];
        cursor.read_exact(&mut buf)?;
        let original_size = u64::from_le_bytes(buf);
        
        cursor.read_exact(&mut buf)?;
        let compressed_size = u64::from_le_bytes(buf);
        
        cursor.read_exact(&mut buf)?;
        let crc64 = u64::from_le_bytes(buf);
        
        let mut file_type_buf = [0u8; 1];
        cursor.read_exact(&mut file_type_buf)?;
        let file_type = match file_type_buf[0] {
            0 => FileType::Regular,
            1 => FileType::Symlink,
            _ => bail!("Unsupported file type: {}", file_type_buf[0]),
        };
        
        let mut mode_buf = [0u8; 4];
        cursor.read_exact(&mut mode_buf)?;
        let mode = u32::from_le_bytes(mode_buf);
        
        cursor.read_exact(&mut buf)?;
        let mtime = u64::from_le_bytes(buf);

        pb.set_message(full_path.display().to_string());

        // Handle symlinks
        if file_type == FileType::Symlink {
            ensure!(compressed_size == 0, "Invalid symlink data");
            let mut target = vec![0u8; original_size as usize];
            cursor.read_exact(&mut target)?;
            
            let mut crc = Digest::new();
            crc.write(&target);
            ensure!(crc.sum64() == crc64, "CRC mismatch for symlink");
            
            fs::create_dir_all(full_path.parent().unwrap_or(output_dir))?;
            if full_path.exists() {
                fs::remove_file(&full_path)?;
            }
            let target_str = String::from_utf8_lossy(&target).into_owned();
            create_symlink(&PathBuf::from(target_str), &full_path)?;
            
            pb.inc(1);
            continue;
        }

        // Extract regular files
        ensure!(
            compressed_size <= MAX_FILE_SIZE,
            "Compressed file too large"
        );
        
        let mut compressed = vec![0u8; compressed_size as usize];
        cursor.read_exact(&mut compressed)?;
        
        let mut decompressed = Vec::with_capacity(original_size as usize);
        let mut decoder = DeflateDecoder::new(&compressed[..]);
        io::copy(&mut decoder, &mut decompressed)?;

        // Verify integrity
        let mut crc = Digest::new();
        crc.write(&decompressed);
        ensure!(crc.sum64() == crc64, "CRC mismatch for file data");

        // Write file
        fs::create_dir_all(full_path.parent().unwrap_or(output_dir))?;
        let mut output_file = File::create(&full_path)?;
        output_file.write_all(&decompressed)?;
        
        // Restore metadata
        set_file_permissions(&full_path, mode)?;
        
        if let Some(sys_time) = UNIX_EPOCH.checked_add(Duration::from_secs(mtime)) {
            filetime::set_file_mtime(&full_path, filetime::FileTime::from_system_time(sys_time))?;
        }

        pb.inc(1);
    }
    pb.finish_with_message("Extraction completed");

    Ok(())
}

// Main Application
fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut password = prompt_password("Password: ")?;

    match cli.command {
        Commands::Compress { path, output } => {
            let input_path = path.canonicalize()?;
            ensure!(input_path.is_dir(), "Input path must be a directory");

            let output_path = output.unwrap_or_else(|| {
                let mut p = input_path.clone();
                p.set_extension("mossad");
                p
            });

            create_archive(&input_path, &output_path, &mut password)?;
            println!("\n✅ Archive created: {}", output_path.display());
        }
        
        Commands::Extract { file, output } => {
            let archive_path = file.canonicalize()?;
            ensure!(archive_path.is_file(), "Archive path must be a file");
            ensure!(
                archive_path.extension().map_or(false, |ext| ext == "mossad"),
                "Invalid archive extension"
            );

            let output_dir = output.unwrap_or_else(|| {
                let mut p = archive_path.clone();
                p.set_extension("");
                p
            });

            fs::create_dir_all(&output_dir)?;
            extract_archive(&archive_path, &output_dir, &mut password)?;
            println!("\n✅ Files extracted to: {}", output_dir.display());
        }
    }

    password.zeroize();
    Ok(())
}
