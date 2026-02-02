mod rounds_keys;
use rounds_keys::ROUND_KEYS ;

mod matrix;
use matrix::{S_BOX,  MIX_COLUMNS_MATRIX,MOD, INV_MIX_COLUMNS_MATRIX, INV_S_BOX, RCON};
use std::fs::OpenOptions;


fn add_round_key(input: [[u8; 4]; 4], key: [[u8; 4]; 4]) -> [[u8; 4]; 4] {
    let mut result = [[0u8; 4]; 4]; 
    for i in 0..4 {
        for j in 0..4 {
            result[i][j] = input[i][j] ^ key[i][j]; 
        }
    }
    result
}

fn shift_rows (input: [[u8; 4]; 4]) -> [[u8; 4]; 4]
{
    let mut result = [[0u8; 4]; 4];
     for i in 0..4 {
        for j in 0..4 {
            result[i][j] = input[i][(j + i) % 4]; 
        }
    }
    result
}

fn rev_shift_rows (input: [[u8; 4]; 4]) -> [[u8; 4]; 4]
{
    let mut result = [[0u8; 4]; 4];
     for i in 0..4 {
        for j in 0..4 {
            result[i][j] = input[i][( j+4-i) % 4]; 
        }
    }
    result
}


fn sub_bytes(sub :[[u8; 16]; 16], input: [[u8;4]; 4]) -> [[u8; 4]; 4 ] 
    {
      let mut  result = [[0u8; 4]; 4];

       for i in 0..4
        {
        for j in 0..4 
        {
                let  row = input[i][j] >> 4;
                let col = input[i][j] & 0x0F;

               result [i][j] = sub[row as usize][col as usize];
        }
       }
       return result;
 
    }


fn dot_prod_mod(a: u16, b: u16) -> u8
{

    let mut  sum = 0u16;
   
   for   i in 0..8
   {
      let mask =(b >> i ) & 1;
      if mask ==1
      {
         sum ^= a << i ;
         
      }
  for i in (8..16).rev()
  {
      if (sum >> i ) & 1 ==1
      {
        sum ^= (MOD as u16) << (i -8);
      }
  }

 
  }
   sum as u8
}
 fn mix_columns(input: [[u8; 4]; 4], matrix: [[u8; 4]; 4])-> [[u8;4];4]
 { 
    let mut  result = [[0u8; 4]; 4];
    
     for col in 0..4
     {

        let  mut  item ;
        for  row in 0..4
        {
                 
                    item =0;
                    for j in 0..4
                    {


                    let a = matrix[row][j] as u16;  
                    let b = input[j][col] as u16;
                    let prod = dot_prod_mod(b, a);
                    item ^= prod;


                  }  
                 result[row][col]= item;
 
         }
     }

    return result;
 }  


fn   aes_encrypt (input: [[u8; 4]; 4], rounds_keys: [[[u8; 4];4 ];11], nr: usize) -> [[u8;4];4]
{
     let  mut  enc= input ;
     
     
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
    
   let r = add_round_key(enc, (rounds_keys[nr]));
  
   r
}
    
    
fn aes_decrypt (input: [[u8; 4]; 4], rounds_keys: [[[u8; 4];4 ];11], nr: usize) -> [[u8;4];4]
{
     let mut dec = input ;

     dec = add_round_key(dec, rounds_keys[nr]);


//  let mut file = OpenOptions::new()
//         .create(true)
//         .write(true)
//         .truncate(true) // clear file at start
//         .open("ciphertext.txt")
//         .expect("Unable to open file");
    
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
    //    writeln!(file, "Round {}:", i+1).unwrap();
    //     for row in &rev_added {
    //         for byte in row {
    //             write!(file, "{:02x} ", byte).unwrap();
    //         }
    //         writeln!(file).unwrap();
    //     }
    //     writeln!(file).unwrap();
    
    // 
    }  
    dec
}    
use std::io::Write;
use std::slice::RSplit;
use std::{rc, result, vec};


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

 fn   key_expansion(key : Vec<u32> , rounds : usize , nk :usize)  -> Vec<u32>{
    let word_count = 4 * (rounds + 1);
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

   let mut result = Vec::with_capacity(rounds + 1);
    result.push(0x00);
    result.push(0x01);

    for  i in   2..=rounds 
    {
         result.push(dot_prod_mod(0x02, result[i -1] as u16));      
    }
    result

}


fn key_bytes_to_word(key: Vec<u8>) -> Vec<u32> {
     
     let size = key.len();
     let mut result = Vec::with_capacity(size);
     for   i in 0..size
     {
        result.push (
                   
                   (key[i] as u32)  << 24 |
                   (key[i] as u32) << 16 |
                   (key[i] as u32) << 8  |
                   (key[i] as u32)) ;
    
     }

  result
}

fn  key_text_to_word(key : u128, size : usize ) -> Vec<u32>
{
    let mut  result = Vec::with_capacity(size / 32);
    let nk = size/32;
    for i in 0..  nk
    { 
            
            result.push(key[i*8]<< 24 |  key[(i+ 1* nk) *8  ] << 16   |  key[(i+ 2*nk) *8  ] << 16 | key[(i+ 3*nk)*8]);
        
         
    }

    result
}


fn key_word_to_bytes(word: [u32; 11]) -> [[u8; 4]; 4]  
    {
       let  mut result = [[0u8; 4]; 4];
       for  col  in 0..4
       {
           result [0][col]= (word [col] >> 24) as u8;
           result [1][col]= (word [col] >> 16) as u8;
           result [2][col]= (word [col] >> 8) as u8;
           result [3][col]= word [col] as u8;   
       }


       result

    }


fn main() {
   
    let input: [[u8; 4]; 4] = [
        [0x32, 0x88, 0x31, 0xe0], 
        [0x43, 0x5a, 0x31, 0x37], 
        [0xf6, 0x30, 0x98, 0x07], 
        [0xa8, 0x8d, 0xa2, 0x34],
    ];

   

    let key: [[u8; 4]; 4] = [
        [0x2b, 0x28, 0xab, 0x09],
        [0x7e, 0xae, 0xf7, 0xcf],
        [0x15, 0xd2, 0x15, 0x4f],
        [0x16, 0xa6, 0x88, 0x3c],
    ];



    let test_key = "2b28ab097eaeff7cf15d2154f16a6883c";

    let r =  key_text_to_word(test_key, 128);
    for i in 0..4
    {
       println!("Key Word {}: {:08x}", i, r[i]);
    }

    // for i in 0..11
    // {
    //    keys[i] = key_word_to_bytes(rounds_keys[i]);
    // }

//  let j = [[0x6d, 0x11, 0xdb, 0xca], 
// [0x88, 0x0b, 0xf9, 0x00], 
// [0xa3, 0x3e, 0x86, 0x93], 
// [0x7a, 0xfd, 0x41, 0xfd],];
//let m = mix_columns(i,MIX_COLUMNS_MATRIX);
//let  encrypted = aes_encrypt(input,keys , 10);
//
//
//let decrypted = aes_decrypt(encrypted, keys, 10);
//
//for row in &decrypted {
//    for byte in row {
//        print!("{:02x} ", byte);
//    }
//    println!();
//}
 //   let added = add_round_key(i, j);
  //  println!("After AddRoundKey: {:02x}", added[1][1]);
  // let sub = sub_bytes(S_BOX,  added);
   // println!("After SubBytes: {:02x}", sub[3][3]);
   //  let shifted = shift_rows(sub);
 //    println!("After ShiftRows: {:02x}", shifted[0][0]);
  //  let   mixed = mix_columns(shifted, MIX_COLUMNS_MATRIX);
 //  let dot1= dot_prod(0xd4, 0x02);
   //   let dot2= dot_prod(0xbf, 0x03);
 //  let dot2= dot_prod(0x5d, 0x01);
 //  let dot3= dot_prod(0x30, 0x01);

  //
  //  println!("After SubBytes: {:02x}", modul(dot2) );
  //println!("After MixColumns: {:02x}", mixed[0][1]);
  //  println!("After MixColumns: {:02x}", mixed[0][0]);
  

}


