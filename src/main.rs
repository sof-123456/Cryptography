
mod matrix;
use matrix::{S_BOX,  MIX_COLUMNS_MATRIX,MOD, INV_MIX_COLUMNS_MATRIX, INV_S_BOX};
use std::fs::OpenOptions;


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
     for i in 0..4 {
            result[i] = input[i]<<8*i  | input[i] >> (32 - 8*i); 
        
    }
    result
}
/* 
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

 fn mix_columns(input: [u32; 4], matrix: [[u8; 4]; 4])-> [u32;4]
 { 
    let mut  result = [0u32; 4];
    
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

/* 
fn   aes_encrypt (input: [[u8; 4]; 4], rounds_keys: &Vec<[[u8; 4];4]>, nr: usize) -> [[u8;4];4]
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
    


   let r = add_round_key(enc, rounds_keys[nr]);
  
   r
}
    
    
fn aes_decrypt (input: [[u8; 4]; 4], rounds_keys: &Vec<[[u8; 4];4 ]>, nr: usize) -> [[u8;4];4]
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

 fn   key_expansion(key : Vec<u32> , rounds : usize )  -> Vec<u32>{
    let word_count = 4 * (rounds + 1);
    let nk  =  key.len()  ; 
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



fn key_bytes_to_word(key: &[u8]) -> Vec<u32> {
     
     let  nk = key.len() / 4 ;
     let mut result = Vec::with_capacity(nk);
     for   i in 0..nk
     {
        result.push (
                   
                   (key[i] as u32)  << 24 |
                   (key[i+4*1] as u32) << 16 |
                   (key[i+4*2] as u32) << 8  |
                   (key[i+4*3] as u32) 
        );
    
     }

  result
}


fn words_to_round_matrices(input : Vec<u32> ) -> Vec<[[u8; 4]; 4]>
{
      let   rounds  = input.len() / 4  ;
      let mut  result = Vec::with_capacity(rounds);

      for i in 0..rounds
      {
          let mut matrix = [[0u8; 4];4];
          for  col  in 0 .. 4
          {
             let word = input[i*4 + col]; 
             matrix[0][col] =(word >> 24) as u8;
             matrix[1][col] =(word >> 16 )as u8;
             matrix[2][col] =(word >> 8) as u8;
             matrix[3][col] = word  as u8   ;
          }
          
         result.push(matrix );

      } 
       
       result 


}

fn aes_rounds(key_len_size : usize) -> usize
{
   match key_len_size
   {
        16 => 10, 
        24 => 12, 
        32 => 14,
        _ =>   panic!("Invalid AES key length"), 
   }
        
}



fn keys_generation(key : &[u8])->   Vec<[[u8; 4]; 4]>
{

   words_to_round_matrices(key_expansion(key_bytes_to_word(&key), key.len() ))

}

fn  loop_encrypt(input: [[u8; 4]; 4] ,  keys : &Vec<[[u8;4 ];4 ]>, nr : usize, block_count : usize) ->  [[u8; 4]; 4]
{
    let mut encrypted = input ;  
    for i in   0.. block_count
    {
        encrypted =  aes_encrypt(encrypted , &keys, nr );
        
    }
   encrypted

}

fn  loop_decrypt(input: [[u8; 4]; 4] ,  keys : &Vec<[[u8;4 ];4 ]>, nr : usize, block_count : usize) ->  [[u8; 4]; 4]
{
    let mut decrypted = input ;  
    for i in   0.. block_count
    {
        decrypted =  aes_decrypt(decrypted , &keys, nr );
        
    }
   decrypted

} 
*/
 use std::io::Write;


 use std::time::Instant;


fn main() {
   
   // let input: [[u8; 4]; 4] = [
   //     [0x32, 0x88, 0x31, 0xe0], 
   //     [0x43, 0x5a, 0x31, 0x37], 
   //     [0xf6, 0x30, 0x98, 0x07], 
   //     [0xa8, 0x8d, 0xa2, 0x34],
   // ];
   let input: [u32; 4] = [0x328831e0,  0x435a3137,  0xf6309807,  0xa88da234];
   /* 
   let key: [u8;  16] = [
        0x2b, 0x28, 0xab, 0x09,
         0x7e
        , 0xae, 0xf7, 0xcf,
        0x15, 0xd2, 0x15, 0x4f,
        0x16, 0xa6, 0x88, 0x3c,       
    ];
*/

    let key =  [ 0x2b28ab09, 0x7eaef7cf, 0x15d2154f, 0x16a6883c];

let  add = add_round_key(input, key);
 let sub = sub_bytes(S_BOX, add);
 let shifted = shift_rows(sub);
for val in shifted.iter() {
    print!("{:08x} ", val);
}
println!();  
//let nr = aes_rounds(key.len());   
//
//let keys =  keys_generation (&key);
//
//
//let start =   Instant::now();
//
//let  encrypted = loop_encrypt(input,  &keys , nr, 65536 );

//let mut blocks = vec![input; 65536];
//
//for block in &mut blocks {
//    *block = aes_encrypt(*block, &keys, nr);
//}
// let duration = start.elapsed();



// println!("Encryption took: {:?} ", duration);

// let decrypted = loop_decrypt(encrypted, &keys, nr,65536 );



   let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true) // clear file at start
        .open("ciphertext.txt")
        .expect("Unable to open file"); 

        

     
    // for row in &encrypted {
    //     for byte in row {
    //         write!(file, "{:02x} ", byte).unwrap();
    //     }
    //     writeln!(file).unwrap();
    // }
    // writeln!(file).unwrap();


  //  for row in &decrypted {
  //      for byte in row {
  //          print!("{:02x} ", byte);
  //      }
  //     println!();
  //  }

}




