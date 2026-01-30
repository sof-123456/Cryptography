mod rounds_keys;
use rounds_keys::ROUND_KEYS ;

mod matrx;
use matrx::{S_BOX,  MIX_COLUMNS_MATRIX,MOD, INV_MIX_COLUMNS_MATRIX, INV_S_BOX};
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
/* 
fn modul (input: u16) -> u8
{    
 
    if (input >>8 ) &1==1
    {
          return (input ^ (MOD as u16))as u8;
    }
    
        return input as u8  ; 
    

}
 */
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


 /*  
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut res: u8 = 0;

    for _ in 0..8 {
        if (b & 1) == 1 {
            res ^= a;
        }

        let hi = a & 0x80;
        a <<= 1;

        // reduction by AES irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11b)
        if hi != 0 {
            a ^= 0x1b;
        }

        b >>= 1;
    }

    res
}
fn mix_columns(input: [[u8; 4]; 4], matrix: [[u8; 4]; 4]) -> [[u8; 4]; 4] {
    let mut result = [[0u8; 4]; 4];

    for col in 0..4 {
        for row in 0..4 {
            let mut val = 0u8;
            for k in 0..4 {
                val ^= gf_mul(matrix[row][k], input[k][col]);
            }
            result[row][col] = val;
        }
    }

    result
}
*/
fn   aes_encrypt (input: [[u8; 4]; 4], rounds_keys: [[[u8; 4]; 4];11], nr: usize) -> [[u8;4];4]
{
     let  mut  enc= input ;

    for i  in 0..nr
    {
        let added = add_round_key(enc, rounds_keys[i]);
        let sub = sub_bytes(S_BOX,  added);
        let  mut shifted = shift_rows(sub);
        if  i !=  nr -1
        {
           shifted  = mix_columns(shifted, MIX_COLUMNS_MATRIX);
            
        }
         enc = shifted;
    }
    
   let r = add_round_key(enc, rounds_keys[10]);
  
   r
}
    
    
fn aes_decrypt (input: [[u8; 4]; 4], rounds_keys: [[[u8; 4]; 4];11], nr: usize) -> [[u8;4];4]
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

fn main() {
   
    let input: [[u8; 4]; 4] = [
        [0x32, 0x88, 0x31, 0xe0], 
        [0x43, 0x5a, 0x31, 0x37], 
        [0xf6, 0x30, 0x98, 0x07], 
        [0xa8, 0x8d, 0xa2, 0x34],
    ];

   

    let key: [[u8; 4]; 4] = [
        [0xf2, 0x7a, 0x59, 0x73],
        [0xc2, 0x96, 0x35, 0x59],
        [0x95, 0xb9, 0x80, 0xf6],
        [0xf2, 0x43, 0x7a, 0x7f]
    ];

    let i = [[0x4b, 0x2c, 0x33, 0x37], 
                            [0x86, 0x4a, 0x9d, 0xd2], 
                            [0x8d, 0x89, 0xf4, 0x18], 
                            [0x6d, 0x80, 0xe8, 0xd8]];



//  let j = [[0x6d, 0x11, 0xdb, 0xca], 
// [0x88, 0x0b, 0xf9, 0x00], 
// [0xa3, 0x3e, 0x86, 0x93], 
// [0x7a, 0xfd, 0x41, 0xfd],];
//let m = mix_columns(i,MIX_COLUMNS_MATRIX);
let result = aes_encrypt(input, ROUND_KEYS, 10);


let decrypted = aes_decrypt(result, ROUND_KEYS, 10);


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


