mod tables;
use crate::tables::{
    INITIAL_PERM, FINAL_PERM, EXPD, PER, SBOX, PC1, PC2, SHIFT_TABLE,
};
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;



#[inline(always)]
fn round (left32:u32,right32: u32,key48:  u64)-> (u32, u32)
{
      let (l, r)=mixer(left32,right32,key48);
      return  swapper(l,r);
   
}
#[inline(always)]
fn swapper ( left32: u32,  right32:u32) -> (u32, u32) 
{         
        
     (right32, left32)
}

#[inline(always)]
fn xor (a: u32, b:u32) -> u32
{
    return a ^b;
}

#[inline(always)]
fn mixer(left32: u32,right32: u32,key48:  u64 )->  (u32, u32)
{
         let new_left = xor(function(right32, key48), left32);
         (new_left, right32)
}

fn s_box(input48:  u64) ->   u32
{
    let mut output32 : u32 = 0;

    for i in 0..8
    {
        let shift =  42 -  i*6 ; 
        let chunk6 = ((input48 >> shift) & 0b111111) as u8;
        let   row= ((chunk6 & 0b100000) >> 4 )  |  (chunk6 & 0b000001);
        let col = (chunk6 & 0b011110 )>>1;
        let val = SBOX[i][row as usize][col as usize] as u32;

        output32 |= val << (28- 4*i );

    } 

    output32 
}
 
fn function(input32 :  u32,  key48 :   u64) ->   u32
{
      
    

    let entended : u64= perm(input32 as u64, &EXPD, 32);
    let xored =  entended ^ key48;
    let  sboxed: u32 = s_box(xored);  

     perm(sboxed as u64,&PER,32 )  as u32 
 
  
}


fn perm(input:  u64, matrix: &[usize], size: u8)   -> u64  {
    let mut result: u64 = 0;

    for (i, &pos) in matrix.iter().enumerate() {
        // Read bit from input (DES uses 1-based indexing)
        let bit = (input >> (size as usize - pos)) & 1;

        // Place bit in output
        result |= bit << (matrix.len() - 1 - i);
    }

    result
}
 
fn split(input: u64, size: u8) -> (u32, u32) {
    let mask: u64 = (1u64 << size) - 1;

    let left  = ((input >> size) & mask) as u32;
    let right = (input & mask) as u32;

    (left, right)
}
#[inline(always)]
fn shift_left(key28: u32, shift: usize) -> u32 {
    //let shift = shift % 28;
    ((key28 << shift) | (key28 >> (28 - shift))) & 0x0FFFFFFF
}
#[inline(always)]
fn combine (key28_1:u32 ,key28_2 : u32 )-> u64
{
     let c = (key28_1 & 0x0FFFFFFF) as u64;
     let b = (key28_2 & 0x0FFFFFFF ) as u64;

      (c << 28 )| b
}
#[inline(always)]
fn compression(key28_1:u32 ,key28_2 : u32 )-> u64  // 48 bit
{   

    let concat = combine(key28_1 , key28_2 ); 
    
    perm(concat, &PC2, 56) 
}

fn key_generator(key: u64) -> [u64; 16] {
    let mut keys: [u64; 16] = [0; 16];

    let key56 = perm(key, &PC1, 64);
    let (mut left28, mut right28) = split(key56, 28);

    for i in 0..16 {
        left28  = shift_left(left28, SHIFT_TABLE[i]);
        right28 = shift_left(right28, SHIFT_TABLE[i]);
        keys[i] = compression(left28, right28);
    }

    keys
}




fn encrypt(plaintext64:  u64, keys: &[u64; 16]) ->   u64
{
     
    let permuted=perm(plaintext64,&INITIAL_PERM, 64);
    let (mut left32, mut right32)= split(permuted, 32);

    for i in 0..16 {
        let (l, r) = round(left32, right32, keys[i]);
        left32 = l;
        right32 = r;
    }

    let pre_output = (right32 as u64) << 32 | (left32 as u64);

    perm(pre_output,&FINAL_PERM, 64)
    
     
}


fn hex_to_bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks(2)
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect()
}
fn encrypt_file_hex(input: &Path, output: &Path, key: u64) -> io::Result<()> {
    let keys = key_generator(key);
    let mut input = File::open(input)?;

    let mut output = File::create(output)?;

    let mut buf = [0u8; 8];
    let mut block_index: u64 = 0;  

    loop {
        let n = input.read(&mut buf)?;

        if n == 0 {
          
            let pad: u8 = 8;
            let mut block_bytes = [pad; 8];
            for i in 0..8 {
                block_bytes[i] ^= (block_index >> (i*8)) as u8;
            }
            let block_u64 = u64::from_be_bytes(block_bytes);
            let enc = encrypt(block_u64, &keys);
            write!(output, "{:016X}", enc)?;
            break;
        }

        if n < 8 {
            let pad = (8 - n) as u8;
            for i in n..8 {
                buf[i] = pad;
            }
        }

        
        let mut block_bytes = buf;
       
        for i in 0..8 {
            block_bytes[i] ^= (block_index >> (i*8)) as u8;
        }

        let block_u64 = u64::from_be_bytes(block_bytes);
        let enc = encrypt(block_u64, &keys);

        block_index += 1;
    }

    Ok(())
}

fn decrypt_file_hex(input: &Path, output: &Path, key: u64) -> io::Result<()> {
    let mut keys = key_generator(key);
    keys.reverse();

    let mut hex = String::new();
    File::open(input)?.read_to_string(&mut hex)?;
    let bytes = hex_to_bytes(&hex);

    let mut out = File::create(output)?;
    let mut block_index: u64 = 0;

    for chunk in bytes.chunks(8) {
        let block_u64 = u64::from_be_bytes(chunk.try_into().unwrap());
        let dec = encrypt(block_u64, &keys); 
        let mut dec_bytes = dec.to_be_bytes();

        for i in 0..8 {
            dec_bytes[i] ^= (block_index >> (i*8)) as u8;
        }

        if block_index == (bytes.len() / 8 - 1) as u64 {
            let pad = dec_bytes[7] as usize;
            out.write_all(&dec_bytes[..8 - pad])?;
        } else {
            out.write_all(&dec_bytes)?;
        }

        block_index += 1;
    }

    Ok(())
}

use std::time::{Duration, Instant};

fn main() -> io::Result<()> {
    let key: u64 = 0xAABB09182736CCDD;

    let input = Path::new("sample.rs");
    let encrypted = Path::new("enc.rs");
    let decrypted = Path::new("dec.rs");


    let metadata = input.metadata()?;
    println!("File size: {} bytes", metadata.len());

     encrypt_file_hex(input, encrypted, key)?;
    println!("Encrypted OK");

    decrypt_file_hex(encrypted, decrypted, key)?;
    println!("Decrypted OK");
  //  println!("?:",encrypt_block(0x7F16B882CBA336F8, keys.reverse()));

    Ok(())
}
 