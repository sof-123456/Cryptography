mod tables;
use crate::tables::{INITIAL_PERM, FINAL_PERM, EXPD, PER, SBOX,PC1, PC2, SHIFT_TABLE};
use std::time::{ Instant};

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

fn encrypt_loop(plaintext:  u64, key: &[u64; 16 ], rounds: usize) ->  u64 { 
    let mut result = plaintext;
    for _ in 0..rounds {
        result = encrypt(result, key);
    }
    result
}


fn encrypt_without_last_perm(plaintext64:  u64, keys: &[u64; 16]) -> u64
{
     
    let (mut left32, mut right32)= split(plaintext64, 32);

    for i in 0..16 {
        let (l, r) = round(left32, right32, keys[i]);
        left32 = l;
        right32 = r;
    }

     (right32 as u64) << 32 | (left32 as u64)    
     
}

fn triple_des(plaintext64: u64 , key1 : &[u64; 16], key2 :&[u64; 16] ) -> u64
{    
    let permuted=perm(plaintext64,&INITIAL_PERM, 64);

    let   phase_1=encrypt_without_last_perm(permuted, key1); 
   

    let   phase_2=encrypt_without_last_perm(phase_1, key2); 

    let   phase_3=encrypt_without_last_perm(phase_2, key1);


    perm(phase_3,&FINAL_PERM, 64)


} 
 

fn main() {
   let   input: u64 = 0x123456ABCD132536;
   let   key1 = 0xAABB09182736CCDD ;
 //  let   key2 = 0xAABB09182736CCD2 ;

//
    let      keys_1 : [u64;  16]= key_generator(key1);
 //  let  mut  keys_2 : [u64;  16]= key_generator(key2);
 //  keys_2.reverse();
   let start= Instant::now();
   let ciphertext = encrypt_loop(input, &keys_1, 131072);
    let end = start.elapsed();
   println!("Time: {:.6} s", end.as_secs_f64() );
    println!("Ciphertext:  0x{:016X}", ciphertext);


  //  let cipher = triple_des(input,&keys_1, &keys_2);
    //keys_1.reverse();
  //  keys_2.reverse();


   // let plaintext = triple_des(cipher,&keys_1, &keys_2);

  // keys.reverse();
  // let plaintext = encrypt_loop(ciphertext, &keys, 128);
 //  println!("Plaintext: 0x{:016X}",plaintext);
 //   println!("{:016X}" , cipher );
   //  println!("{:016X}" ,   plaintext); 
  
}