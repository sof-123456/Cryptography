mod tables;
use crate::tables::{INITIAL_PERM, FINAL_PERM, EXPD, PER, SBOX,PC1, PC2, SHIFT_TABLE};

fn key_to_bits(key: u128) -> Vec<u8> {
    let mut bits = Vec::with_capacity(64);
    for i in (0..64).rev() {
        bits.push(((key >> i) & 1) as u8);
    }
    bits
}
fn key_bit_hex(key_bits: &Vec::<u8>) ->  String 
{
 let mut hex_string = String::new();

 for chunk in key_bits.chunks(4) {
    let mut value = 0;
    for &bit in chunk {
        value = (value << 1) | bit;
    }
    hex_string.push_str(&format!("{:X}", value));
}    
    hex_string        
}


fn split (input :Vec<u8>, len :usize ) -> (Vec<u8>, Vec<u8>)
{
      return (input[..len].to_vec(), input[len..].to_vec()); 
}



//fn shift_left(key28: &mut Vec<u8>,  shift : usize) 
//{
//      
//           for  _  in   0..shift
//           {
//                let  first = key28.remove(0) ;
//                key28.push(first);
//           }
//
//}
fn shift_left(key28: &mut [u8], shift: usize) {
    key28.rotate_left(shift);
}



fn compression(key28_1:&Vec<u8> ,key28_2 : &Vec<u8>) -> Vec<u8> 
{
    let  mut  concat =  Vec::with_capacity(56);
    let  mut  result_key =  Vec::with_capacity(48);
    concat.extend(key28_1);
    concat.extend(key28_2);
    
    for &rec in PC2.iter()
    {
         result_key.push(concat[rec-1]);
    }
    result_key 
}

fn  key_generator(key : u128) -> Vec::<Vec::<u8>>
{
    let  mut  keys = Vec::<Vec::<u8>>::with_capacity(16);
    let key56=permutation(key_to_bits(key), &PC1);

    let (mut left28, mut right28)  = split (key56, 28) ;

    for  i in 0..16
    {
       shift_left(&mut left28, SHIFT_TABLE[i]);
       shift_left(&mut right28,SHIFT_TABLE[i]);
       keys.push(compression(&left28,&right28));
    
        
              
    }
     keys
}

//fn   xor( key:  Vec<u8>, input: Vec<u8> ) -> Vec<u8>
//{
//        let  mut result   =   Vec::with_capacity(key.len()) ;
//        for   (i, j)  in  key.iter().zip(input.iter())
//            {     result.push(i ^ j);}      
//                 
//          result              
//}

fn xor (a: Vec<u8>, b: Vec<u8>) -> Vec<u8>
{
    let mut result = Vec::with_capacity(a.len());
    for (bit_a, bit_b) in a.iter().zip(b.iter()) {
        result.push(bit_a ^ bit_b);
    }
    result
}

fn swapper (mut left32: Vec<u8>, mut right32:Vec<u8>) -> (Vec<u8>, Vec<u8>) 
{         
        let  tmp:Vec<u8> =left32;
        left32=right32;
        right32= tmp;
        
     (left32, right32)
}

fn bits_to_int(bits: &[u8]) -> usize {
    bits.iter().fold(0, |acc, &b| (acc << 1) | b as usize)
}
fn s_box(input48: Vec<u8>) -> Vec<u8>
{
     let mut result = Vec::with_capacity(32);

    for  (i,chunk) in input48.chunks(6).enumerate()
    {
       let row = bits_to_int(&[chunk[0], chunk[5]]);
       let col = bits_to_int(&chunk[1..5]);

        let val = SBOX[i][row][col];
        for bit in (0..4).rev() {
            result.push(((val >> bit) & 1) as u8);
        }
    }
    result
}

fn permutation (input:Vec<u8>,  matrix:  &[usize])-> Vec<u8>
{
   
    let mut output = Vec::with_capacity(matrix.len());
    for &i in matrix.iter()
    {
        output.push(input[i-1]);
    }
    return output;
}

fn function(input32 :Vec<u8>,  key48 : Vec<u8>) -> Vec<u8>
{
      return  permutation(s_box(xor(permutation(input32, &EXPD),key48 )),&PER );

  
}
fn mixer(left32:Vec<u8>,right32:Vec<u8>,key48:Vec<u8> )->(Vec<u8>,Vec<u8>)
{
         let new_left = xor(function(right32.clone(), key48), left32);
         (new_left, right32)
}

fn round (left32:Vec<u8>,right32:Vec<u8>,key48:Vec<u8>)-> (Vec<u8>, Vec<u8>)
{
      let (l, r)=mixer(left32,right32,key48);
      return  swapper(l,r);
   
}



fn encrypt(plaintext64: Vec<u8>, keys: &[Vec<u8>]) -> Vec<u8>
{
     let mut result = Vec::with_capacity(64);

     let perm_initial=permutation(plaintext64,&INITIAL_PERM);
     let (mut left32, mut right32)= split(perm_initial, 32);
      
  
  //   let keys = key_generator(key64);


   // let mut input = String::new();

//use::std::io;

     for   i     in   0..15
     {
        
        (left32, right32)=round(left32, right32, keys[i].clone());
        
    //     io::stdin().read_line(&mut input);
     }
     left32 = xor(function(right32.clone(), keys[15].clone()), left32);
     result.extend(left32);
     result.extend(right32);
     
     result =permutation(result,&FINAL_PERM);
      result
     
}

fn decrypt(ciphertext64: Vec<u8>, key64: u128) -> Vec<u8> {
    let permuted = permutation(ciphertext64, &INITIAL_PERM);
    let (mut left32, mut right32) = split(permuted, 32);

    let keys = key_generator(key64);

    for i in (1..16).rev() {
        let (l, r) = mixer(left32.clone(), right32.clone(), keys[i].clone());
        left32 = r;  
        right32 = l;
    }

    
    left32 = xor(function(right32.clone(), keys[0].clone()), left32);

    let mut preoutput = Vec::with_capacity(64);
    preoutput.extend(left32);
    preoutput.extend(right32);

    permutation(preoutput, &FINAL_PERM)
}

fn bytes_to_bits(bytes: &[u8; 8]) -> Vec<u8> {
    let mut bits = Vec::with_capacity(64);
    for &b in bytes.iter() {
        for i in (0..8).rev() {
            bits.push((b >> i) & 1);
        }
    }
    bits
}

//fn encrypt_text(plaintext: &str, key: u128) -> Vec<u8> {
//    let mut result = Vec::new();
//    let bytes = plaintext.as_bytes();
//
//    for chunk in bytes.chunks(8) {
//        let mut block = [0u8; 8]; // DES block
//
//        // zero padding
//        for i in 0..chunk.len() {
//            block[i] = chunk[i];
//        }
//
//        let block_bits = bytes_to_bits(&block);
//        let encrypted = encrypt(block_bits, key);
//
//
//        result.extend(encrypted);
//        result
//   
// }
    fn bits_to_bytes(bits: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for chunk in bits.chunks(8) {
        let mut value = 0u8;
        for &b in chunk {
            value = (value << 1) | b;
        }
        bytes.push(value);
    }
    bytes
}

//fn decrypt_text(cipher_bits: &[u8], key: u128) -> String {
//    let mut plaintext_bytes = Vec::new();
//
//    for block in cipher_bits.chunks(64) {
//        let decrypted_bits = decrypt(block.to_vec(), key);
//        let bytes = bits_to_bytes(&decrypted_bits);
//        plaintext_bytes.extend(bytes);
//    }
//
//    while plaintext_bytes.last() == Some(&0) {
//        plaintext_bytes.pop();
//    }
//
//    String::from_utf8(plaintext_bytes).unwrap()
//}

fn encrypt_loop(plaintext: Vec<u8>, key: &[Vec<u8>], rounds: usize) -> Vec<u8> { 
    let mut result = plaintext;
    for _ in 0..rounds {
        result = encrypt(result, key);
    }
    result
}


fn decrypt_loop(plaintext: Vec<u8>, key: u128, rounds: usize) -> Vec<u8> { 
    let mut result = plaintext;
    for _ in 0..rounds {
        result = decrypt(result, key);
    }
    result
}
use std::time::{Duration, Instant};
fn main() {

  //  let plaintext = "Process is program in execution and does specific task. The process changes may states during it’s life time and the final state for a process is Terminated state when it exits and no longer available in memory.j";


    let plaintext: u128 =0x123456ABCD132536;  

    let key: u128 = 0xAABB09182736CCDD;
    let keys = key_generator(key);

    let duration = Instant::now();

  
    let  result=   encrypt_loop(key_to_bits(plaintext), &keys, 100000);

    let duration = duration.elapsed();
     println!("Execution time: {:.3?}", duration);
    println!("Encrypted (HEX): {}", key_bit_hex(&result));
    let decrypt = decrypt_loop(result, key,100000 );
    println!("Decrypted (HEX): {}", key_bit_hex(&decrypt));



}

 
 
