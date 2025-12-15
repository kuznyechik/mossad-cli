use anyhow::{bail, ensure, Context, Result};
use argon2::{Argon2, Params};
use cipher::{KeyIvInit, StreamCipher};
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
    fs::{self, File},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};
use walkdir::WalkDir;
use zeroize::Zeroize;

const MAGIC: &[u8; 4] = b"MOSS";
const VERSION: u8 = 4;
const FLAG_COMPRESS: u8 = 0b0000_0001;

const MAX_FILES: u32 = 1_000_000;
const MAX_PATH_LEN: usize = 4096;
const MAX_FILE_SIZE: u64 = 1 << 40;

// === CLI ===
#[derive(Parser)]
#[command(
    name = "mossad",
    version = "1.0",
    about = "Archive chiffrée .mossad (Kuznyechik CTR)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    Compress { path: PathBuf },
    Extract { file: PathBuf },
}

// === UTILS ===
type HmacSha256 = Hmac<Sha256>;

fn write_u16(w: &mut impl Write, v: u16) -> io::Result<()> {
    w.write_all(&v.to_le_bytes())
}
fn write_u32(w: &mut impl Write, v: u32) -> io::Result<()> {
    w.write_all(&v.to_le_bytes())
}
fn write_u64(w: &mut impl Write, v: u64) -> io::Result<()> {
    w.write_all(&v.to_le_bytes())
}
fn read_u16(r: &mut impl Read) -> io::Result<u16> {
    let mut b = [0; 2];
    r.read_exact(&mut b)?;
    Ok(u16::from_le_bytes(b))
}
fn read_u32(r: &mut impl Read) -> io::Result<u32> {
    let mut b = [0; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}
fn read_u64(r: &mut impl Read) -> io::Result<u64> {
    let mut b = [0; 8];
    r.read_exact(&mut b)?;
    Ok(u64::from_le_bytes(b))
}

fn derive_keys(password: &mut String, salt: &[u8], m: u32, t: u32, p: u32) -> ([u8; 32], [u8; 32]) {
    let params = Params::new(m, t, p, None).expect("argon params");
    let argon = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = [0u8; 64];
    argon
        .hash_password_into(password.as_bytes(), salt, &mut out)
        .expect("argon2");
    password.as_mut_str().zeroize();
    let mut enc = [0u8; 32];
    let mut mac = [0u8; 32];
    enc.copy_from_slice(&out[..32]);
    mac.copy_from_slice(&out[32..]);
    out.zeroize();
    (enc, mac)
}

// === CORE ===
fn encrypt_folder(input: &Path, password: &mut String) -> Result<PathBuf> {
    ensure!(input.is_dir(), "Le chemin doit être un dossier");

    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let (m_cost, t_cost, p_cost) = (64 * 1024, 3, 1);
    let (k_enc, k_mac) = derive_keys(password, &salt, m_cost, t_cost, p_cost);
    let mut cipher = Ctr128BE::<Kuznyechik>::new(&k_enc.into(), &nonce.into());

    let files: Vec<_> = WalkDir::new(input)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e: &walkdir::DirEntry| e.file_type().is_file())
        .collect();

    ensure!(files.len() as u32 <= MAX_FILES, "Trop de fichiers");

    let pb = ProgressBar::new(files.len() as u64);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner} [{elapsed}] [{bar:40.cyan/blue}] {pos}/{len} {msg}",
        )
        .unwrap(),
    );

    let mut payload = Vec::new();
    write_u32(&mut payload, files.len() as u32)?;

    for entry in files {
        let rel = entry
            .path()
            .strip_prefix(input)
            .context("Chemin invalide")?;
        let rel = rel.to_string_lossy();
        ensure!(rel.len() <= MAX_PATH_LEN, "Chemin trop long");
        pb.set_message(rel.to_string());

        let mut f = File::open(entry.path())?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;
        ensure!(buf.len() as u64 <= MAX_FILE_SIZE, "Fichier trop gros");

        let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&buf)?;
        let compressed = enc.finish()?;

        let mut crc = Digest::new();
        crc.write(&buf);
        let crc64 = crc.sum64();

        write_u16(&mut payload, rel.len() as u16)?;
        payload.write_all(rel.as_bytes())?;
        write_u64(&mut payload, buf.len() as u64)?;
        write_u64(&mut payload, compressed.len() as u64)?;
        write_u64(&mut payload, crc64)?;
        payload.write_all(&compressed)?;

        pb.inc(1);
    }
    pb.finish_with_message("Chiffrement");

    cipher.apply_keystream(&mut payload);

    // --- HEADER ---
    let flags = FLAG_COMPRESS;
    let header_len: u16 = 4 + 1 + 1 + 2 + 16 + 16 + 4 + 4 + 4;

    let mut header = Vec::new();
    header.extend_from_slice(MAGIC);
    header.push(VERSION);
    header.push(flags);
    write_u16(&mut header, header_len)?;
    header.extend_from_slice(&nonce);
    header.extend_from_slice(&salt);
    write_u32(&mut header, m_cost)?;
    write_u32(&mut header, t_cost)?;
    write_u32(&mut header, p_cost)?;

    let mut mac = HmacSha256::new_from_slice(&k_mac).unwrap();
    mac.update(&header);
    mac.update(&payload);
    let tag = mac.finalize().into_bytes();

    let mut out = Vec::new();
    out.extend_from_slice(&header);
    out.extend_from_slice(&tag);
    write_u64(&mut out, payload.len() as u64)?;
    out.extend_from_slice(&payload);

    let mut outp = input.to_path_buf();
    outp.set_extension("mossad");
    fs::write(&outp, out)?;
    Ok(outp)
}

fn decrypt_file(input: &Path, password: &mut String) -> Result<()> {
    let mut data = Vec::new();
    File::open(input)?.read_to_end(&mut data)?;
    ensure!(&data[..4] == MAGIC, "Pas un fichier .mossad");
    ensure!(data[4] == VERSION, "Version non supportée");

    let header_len = u16::from_le_bytes([data[6], data[7]]) as usize;
    let header = &data[..header_len];
    let tag = &data[header_len..header_len + 32];
    let payload_size =
        u64::from_le_bytes(data[header_len + 32..header_len + 40].try_into().unwrap()) as usize;
    let payload = &data[header_len + 40..header_len + 40 + payload_size];

    let nonce = &header[8..24];
    let salt = &header[24..40];
    let m = u32::from_le_bytes(header[40..44].try_into().unwrap());
    let t = u32::from_le_bytes(header[44..48].try_into().unwrap());
    let p = u32::from_le_bytes(header[48..52].try_into().unwrap());

    let (k_enc, k_mac) = derive_keys(password, salt, m, t, p);

    let mut mac = HmacSha256::new_from_slice(&k_mac).unwrap();
    mac.update(header);
    mac.update(payload);
    if mac.verify_slice(tag).is_err() {
        bail!("Gros nul c'est pas le bon mdp");
    }

    let mut plain = payload.to_vec();
    let mut cipher = Ctr128BE::<Kuznyechik>::new(&k_enc.into(), nonce.into());
    cipher.apply_keystream(&mut plain);

    let mut cur = io::Cursor::new(plain);
    let count = read_u32(&mut cur)?;
    ensure!(count <= MAX_FILES, "Fichier corrompu");

    for _ in 0..count {
        let l = read_u16(&mut cur)? as usize;
        ensure!(l > 0 && l <= MAX_PATH_LEN, "Chemin invalide");
        let mut p = vec![0u8; l];
        cur.read_exact(&mut p)?;
        let path = PathBuf::from(String::from_utf8(p)?);

        let orig = read_u64(&mut cur)?;
        ensure!(orig <= MAX_FILE_SIZE, "Taille invalide");
        let clen = read_u64(&mut cur)? as usize;
        let crc = read_u64(&mut cur)?;

        let mut c = vec![0u8; clen];
        cur.read_exact(&mut c)?;
        let mut dec = DeflateDecoder::new(&c[..]);
        let mut out = Vec::with_capacity(orig as usize);
        dec.read_to_end(&mut out)?;

        let mut d = Digest::new();
        d.write(&out);
        ensure!(d.sum64() == crc, "CRC invalide");
        fs::create_dir_all(path.parent().unwrap_or(Path::new(".")))?;
        fs::write(&path, out)?;
    }
    Ok(())
}

// === MAIN ===
fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Command::Compress { path } => {
            let mut pwd = prompt_password("Mot de passe : ")?;
            let out = encrypt_folder(&path, &mut pwd)?;
            println!(
                "
✅ Archive créée : {:?}",
                out
            );
        }
        Command::Extract { file } => {
            let mut pwd = prompt_password("Mot de passe : ")?;
            decrypt_file(&file, &mut pwd)?;
            println!(
                "
✅ Extraction terminée"
            );
        }
    }
    Ok(())
}
