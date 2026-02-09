
mod matrix;
use matrix::{S_BOX,  MIX_COLUMNS_MATRIX,MOD, INV_MIX_COLUMNS_MATRIX, INV_S_BOX};


fn add_round_key(input: [u32; 4], key: [u32; 4]) -> [u32; 4] {
    let mut result = [0u32; 4]; 
    for i in 0..4 {
        result[i] = input[i] ^ key[i]; 
    }
    result
}

fn shift_rows (input: [u32; 4]) -> [u32; 4]
{
    let mut result = [0u32; 4];
    result[0] = input[0];
     for i in 1..4 {
            result[i] =  (input[i]<< 8*i ) | (input[i] >> (32 - 8*i) ); 
        
    }
    result
}

fn rev_shift_rows (input: [u32; 4]) -> [u32; 4]
{
    let mut result = [0u32; 4];
    result[0] = input[0];

     for i in 1..4 {
        result[i] = (input[i] >> (8*i)) | (input[i] << (32 - 8*i));
    }
    result
}
    /* 
    fn rev_shift_rows(input: [u32; 4]) -> [u32; 4] {
    let mut result = [0u32; 4];

    for i in 0..4 {
        result[i] = input[i].rotate_right(8 * i as u32);
    }

    result
}
*/
     


fn sub_bytes(sub :[[u8; 16]; 16], input: [u32; 4]) -> [u32; 4] 
    {
      let mut  result = [0u32; 4];
      let mut tmp=0;
       for i in 0..4
        {
        for j in 0..4 
        {
                let  row = (input[i] >> (8*j + 4)) & 0x0F;
                let  col = (input[i] >> (8*j)) & 0x0F;

                tmp |= (sub[row as usize][col as usize] as u32) << (8*j);

        }
        result[i] = tmp;
        tmp=0;

       }
       return result;
 
    }

#[inline]
fn dot_prod_mod(a: u8, b: u8) -> u8 {
    let mut sum: u16 = 0;

    // multiply
    for i in 0..8 {
        if ((b >> i) & 1) != 0 {
            sum ^= (a as u16) << i;
        }
    }

    // reduce modulo AES polynomial
    for i in (8..16).rev() {
        if ((sum >> i) & 1) != 0 {
            sum ^= (MOD as u16) << (i - 8);
        }
    }

    sum   as u8 
}


fn mix_columns(input: [u32; 4], matrix: [[u8; 4]; 4]) -> [u32; 4] {
      let mut result = [0u32; 4];

       for  i in 0..4
       
       {

         let mut  result_word = 0u32;
          for row in 0.. 4 
          {
              let mut item = 0u32;

              item =((dot_prod_mod(((input[row] >> 24 )& 0xFF) as u8, matrix[i][row]) as u32) << 24)
                    | ((dot_prod_mod(((input[row] >> 16 )& 0xFF) as u8, matrix[i][row])) as u32) << 16
                   |  ((dot_prod_mod(((input[row] >> 8 ) as u8)& 0xFF, matrix[i][row]))  as u32)<< 8
                   | ((dot_prod_mod((input[row] & 0xFF) as u8, matrix[i][row])as u32));

                 result_word  ^= item;
            }
            result[i] = result_word;
       }

result


 }

    
fn   encrypt (input: [u32; 4], rounds_keys:&Vec<[u32; 4]> , nr: usize) -> [u32;4]
{
     let  mut  enc = input ;
    

    for  round   in 0..nr
    {   

        let added = add_round_key(enc, rounds_keys[round]);
        let sub = sub_bytes(S_BOX,  added);
        let  mut shifted = shift_rows(sub);
        if   round !=  nr -1
        {
           shifted  = mix_columns(shifted, MIX_COLUMNS_MATRIX);
            
        }
         enc = shifted;
    }
    


   let r = add_round_key(enc, rounds_keys[nr]);
  
   r
}
   
fn aes_encrypt(input: [u32; 4], rounds_keys:&Vec<[u32; 4]>) -> [u32; 4]
{ let mut nr;

    match rounds_keys.len() {
        11 => nr = 10, // AES-128
        13 => nr = 12, // AES-192
        15 => nr = 14, // AES-256
        _ => panic!("Invalid number of round keys"),
    }
    encrypt(input, rounds_keys, nr)
}

fn   decrypt (input: [u32; 4],rounds_keys:&Vec<[u32; 4]>, nr: usize) ->[u32;4]
{
     let mut dec = input ;

     dec = add_round_key(dec, rounds_keys[nr]);
    
    
     for i  in (0..nr).rev()
     {
        let   rev_shifted = rev_shift_rows(dec); 
        let  rev_sub = sub_bytes(INV_S_BOX,  rev_shifted);
        let  mut  rev_added = add_round_key(rev_sub, rounds_keys[i]);
        if i != 0
        {
           rev_added = mix_columns( rev_added, INV_MIX_COLUMNS_MATRIX);
        }
      dec = rev_added;
      
   
    }  
    dec
}    

fn aes_decrypt(input: [u32; 4], rounds_keys:&Vec<[u32; 4]>) -> [u32; 4]
{ let mut nr;

    match rounds_keys.len() {
        11 => nr = 10, // AES-128
        13 => nr = 12, // AES-192
        15 => nr = 14, // AES-256
        _ => panic!("Invalid number of round keys"),
    }
    decrypt(input, rounds_keys, nr)
}

fn  left_rot (input:   u32) -> u32
{
     let mut result = input;
     result = (result << 8) | (result >> 24);
     result
}



 fn  sub_words (  input : u32 ) -> u32
 {

     let mut result =  0u32;

     for i in (0..4).rev()
     { 
         let row = ( input>> (i*8 + 4)) as usize & 0xF;
         let col = (input >> (i*8)) as usize & 0xF;
         result |= (S_BOX[row][col] as u32) << (i*8);
     }
      result
 }



 fn   key_expansion(key : &[u32] , rounds : usize )  -> Vec<u32>{
    let word_count = 4 * (rounds + 1);
    let nk  =  key.len() ; 
    let mut result = vec![0u32; word_count];

     for i in 0 .. nk 
     {
        result[i] = key[i];
     }
      

    let rcon = rcon_gen(rounds);
      for  i  in    nk..word_count
        {

            let mut  temp = result[i -1];
             if i %  nk ==0
             {
                temp  = sub_words(left_rot(temp)) ^ (rcon[i / nk ] as u32) <<24   ;
             } 

             //aes 256
             else if nk == 8 && i % nk == 4
             {
               temp = sub_words(temp);
             }
            result [i] = result [i - nk ] ^ temp;            
  
        }
               
            result
        }

fn rcon_gen(rounds: usize) -> Vec<u8>

{

  let mut  result = Vec::with_capacity(rounds+1 );


    result.push(0x00);
    result.push(0x01);

    for  i in   2..=rounds 
    {
         result.push(dot_prod_mod(0x02, result[i -1] as u8));      
    }
    result

}

fn keys_generation(key: &[u32]) -> Vec<[u32; 4]> {
    let nr = match key.len() {
        4 => 10,
        6 => 12,
        8 => 14,
        _ => panic!("Invalid AES key size"),
    };

    words_to_round_matrices(key_expansion(key, nr))
}




fn words_to_round_matrices(input : Vec<u32> ) -> Vec<[u32; 4]>
{
      let   rounds  = input.len() / 4  ;
      let mut  result = Vec::with_capacity(rounds);

 for i in 0..rounds   

      {
          let mut matrix = [0u32;4];
    for   row  in 0 .. 4

          {
              
             matrix[row] = 
              (((input[4  *i ] >>  (8*(3-row)))  & 0xFF) <<  24)
             | (((input[4  *i+1] >>(8*(3-row)))  & 0xFF ) << 16)
             | (((input[4  *i+2] >>  (8*(3-row)))   & 0xFF) << 8)
             | (((input[4  *i+3] >> (8*(3-row)))  &  0xFF) )
             ;   

          }
          
         result.push(matrix );

      } 
       
       result 
}


fn  loop_encrypt(input: [u32;4] ,  keys:&Vec<[u32; 4]>, block_count : usize) ->  [u32;4]
{
    let mut encrypted = input ;  
    for i in   0.. block_count
    {
        encrypted =  aes_encrypt(encrypted , &keys); 
        
    }
   encrypted

}

fn  loop_decrypt(input: [u32;4] ,  keys : &Vec<[u32; 4]>, block_count : usize) ->  [u32;4]
{
    let mut decrypted = input ;  
    for i in   0.. block_count
    {
        decrypted =  aes_decrypt(decrypted , &keys );
        
    }
   decrypted

} 

 use std::io::Write;


use std::mem::swap;
use std::result;
use std::time::Instant;


fn main() {
   
   let input: [u32; 4] = [0x328831e0,  0x435a3137,  0xf6309807,  0xa88da234]; // by rows 
    
   
  let key = vec![
    0x2b7e1516,
    0x28aed2a6,
    0xabf71588,
    0x09cf4f3c,
]; // by columns 

let keys = keys_generation(&key);


let start =   Instant::now();

let  encrypted = loop_encrypt(input,  &keys ,  65536 );
let duration: std::time::Duration = start.elapsed();


for i in 0..4{
    println!("{:08x} ", encrypted[i]);
}


println!("Encryption took: {:?} ", duration);

let decrypted = loop_decrypt(encrypted, &keys,65536 );
 for i  in &decrypted  {
    println!("{:08x} ", i);
     
 }


}




