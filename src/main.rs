mod tables;
use crate::tables::{
    INITIAL_PERM, FINAL_PERM, EXPD, PER, SBOX, PC1, PC2, SHIFT_TABLE,
};

use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;

/* ===================== DES CORE ===================== */

#[inline(always)]
fn round(left: u32, right: u32, key: u64) -> (u32, u32) {
    let new_left = left ^ function(right, key);
    (right, new_left)
}

fn function(input32: u32, key48: u64) -> u32 {
    let expanded = perm(input32 as u64, &EXPD, 32);
    let xored = expanded ^ key48;
    let sboxed = s_box(xored);
    perm(sboxed as u64, &PER, 32) as u32
}

fn s_box(input48: u64) -> u32 {
    let mut out = 0u32;

    for i in 0..8 {
        let shift = 42 - i * 6;
        let chunk = ((input48 >> shift) & 0x3F) as u8;
        let row = ((chunk & 0x20) >> 4) | (chunk & 1);
        let col = (chunk >> 1) & 0x0F;
        let val = SBOX[i][row as usize][col as usize] as u32;
        out |= val << (28 - i * 4);
    }
    out
}

fn perm(input: u64, table: &[usize], size: u8) -> u64 {
    let mut out = 0u64;
    for (i, &pos) in table.iter().enumerate() {
        let bit = (input >> (size as usize - pos)) & 1;
        out |= bit << (table.len() - 1 - i);
    }
    out
}

fn split(input: u64) -> (u32, u32) {
    ((input >> 32) as u32, input as u32)
}

fn encrypt_block(block: u64, keys: &[u64; 16]) -> u64 {
    let permuted = perm(block, &INITIAL_PERM, 64);
    let (mut l, mut r) = split(permuted);

    for i in 0..16 {
        let (nl, nr) = round(l, r, keys[i]);
        l = nl;
        r = nr;
    }

    let pre_output = (r as u64) << 32 | (l as u64);
    perm(pre_output, &FINAL_PERM, 64)
}

fn key_generator(key: u64) -> [u64; 16] {
    let mut keys = [0u64; 16];
    let key56 = perm(key, &PC1, 64);
    let mut c = (key56 >> 28) as u32 & 0x0FFFFFFF;
    let mut d = key56 as u32 & 0x0FFFFFFF;

    for i in 0..16 {
        c = ((c << SHIFT_TABLE[i]) | (c >> (28 - SHIFT_TABLE[i]))) & 0x0FFFFFFF;
        d = ((d << SHIFT_TABLE[i]) | (d >> (28 - SHIFT_TABLE[i]))) & 0x0FFFFFFF;
        let cd = ((c as u64) << 28) | d as u64;
        keys[i] = perm(cd, &PC2, 56);
    }
    keys
}

/* ===================== HEX HELPERS ===================== */

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect()
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks(2)
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect()
}

/* ===================== FILE ENCRYPT ===================== */

fn encrypt_file_hex(input: &Path, output: &Path, key: u64) -> io::Result<()> {
    let keys = key_generator(key);
    let mut input = File::open(input)?;
    let mut output = File::create(output)?;

    let mut buf = [0u8; 8];

    loop {
        let n = input.read(&mut buf)?;

        if n == 0 {
            let pad = 8u8;
            let block = u64::from_be_bytes([pad; 8]);
            let enc = encrypt_block(block, &keys);
            write!(output, "{:016X}", enc)?;
            break;
        }

        if n < 8 {
            let pad: u8 = (8 - n) as u8;
            for i in n..8 {
                buf[i] = pad;
            }
            let block = u64::from_be_bytes(buf);
            let enc = encrypt_block(block, &keys);
            write!(output, "{:016X}", enc)?;
            break;
        }

        let block = u64::from_be_bytes(buf);
        let enc = encrypt_block(block, &keys);
        write!(output, "{:016X}", enc)?;
    }
    Ok(())
}

/* ===================== FILE DECRYPT ===================== */

fn decrypt_file_hex(input: &Path, output: &Path, key: u64) -> io::Result<()> {
    let mut keys = key_generator(key);
    keys.reverse(); 

    let mut hex = String::new();
    File::open(input)?.read_to_string(&mut hex)?;
    let bytes = hex_to_bytes(&hex);


    let mut out = File::create(output)?;

    for (i, chunk) in bytes.chunks(8).enumerate() {
        let block = u64::from_be_bytes(chunk.try_into().unwrap());
        let dec = encrypt_block(block, &keys);
        let out_bytes = dec.to_be_bytes();

        if i == bytes.len() / 8 - 1 {
            let pad = out_bytes[7] as usize;
            out.write_all(&out_bytes[..8 - pad])?;
        } else {
            out.write_all(&out_bytes)?;
        }
    }
    Ok(())
}

/* ===================== MAIN ===================== */

fn main() -> io::Result<()> {
    let key: u64 = 0xAABB09182736CCDD;

    let input = Path::new("C:/Users/Lenovo ThinkBook/Desktop/rust_proj/src/test.txt");
    let encrypted = Path::new("C:/Users/Lenovo ThinkBook/Desktop/rust_proj/src/result_hex.txt");
    let decrypted = Path::new("C:/Users/Lenovo ThinkBook/Desktop/rust_proj/src/decrypt.txt");


    let metadata = input.metadata()?;
    println!("File size: {} bytes", metadata.len());

     encrypt_file_hex(input, encrypted, key)?;
    println!("Encrypted OK");

    decrypt_file_hex(encrypted, decrypted, key)?;
    println!("Decrypted OK");
  //  println!("?:",encrypt_block(0x7F16B882CBA336F8, keys.reverse()));

    Ok(())
}
