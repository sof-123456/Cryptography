mod tables;
use tables::{EXP_TABLE, LOG_TABLE, M, KEYS, M_INVERSE,BIASES};
 



    fn addition(input: [u8; 16], key: [u8; 16], key_round: usize) -> [u8; 16] {

    let mut sum_byte = [0u8; 16];
    for i in 0..16 {
        let is_xor_pos = (i % 4 == 0) || (i % 4 == 3);
        
        if key_round == 1 {
            sum_byte[i] = if is_xor_pos { input[i] ^ key[i] } else { input[i].wrapping_add(key[i]) };
        } else {
            
            sum_byte[i] = if is_xor_pos { input[i].wrapping_add(key[i]) } else { input[i] ^ key[i] };
        }
    }
    sum_byte
}

fn substitution(input: [u8; 16], key: [u8; 16], key_round: usize) -> [u8; 16] {
    let mut result = [0u8; 16];
    for i in 0..16 {
        let is_xor_type = (i % 4 == 0) || (i % 4 == 3);
        if key_round == 1 {
            result[i] = if is_xor_type { input[i] ^ key[i] } else { input[i].wrapping_sub(key[i]) };
        } else {
            result[i] = if is_xor_type { input[i].wrapping_sub(key[i]) } else { input[i] ^ key[i] };
        }
    }
    result
}

    fn  exponent (input : [u8; 16], order : usize ) -> [u8; 16]
    {
        let  mut exp_byte = [0u8; 16] ;
  if  order==1 
  {
    for  i in 0 .. 16 
    {

           
            let out_byte= if  (i % 4 ==0)  || (i % 4 == 3 )  
            {
                EXP_TABLE[input[i] as usize] 
            }
            else
            {
                LOG_TABLE[input[i] as usize] 
            };
                    exp_byte[i] = out_byte;

    }

}
else
{
    for  i in 0 .. 16 
    {


            let out_byte= if  (i % 4 ==0)  || (i % 4 == 3 )  
            {
                LOG_TABLE[input[i] as usize] 
            }
            else
            {
                EXP_TABLE[input[i] as usize] 
            };
                    exp_byte[i] = out_byte;

    } 
}
    exp_byte
    }

fn matrix_mul(x: [u8; 16], m: [[u8; 16]; 16]) -> [u8; 16] {
    let mut result = [0u8; 16];

    for j in 0..16 { // column of matrix
        let mut sum: u8 = 0;
        for i in 0..16 { // row of matrix
            let term = x[i].wrapping_mul(m[i][j]);
            sum = sum.wrapping_add(term);
        }
        result[j] = sum;
    }

    result
}


    use std::io::{self, Write};

    fn  encrypt (input : [u8; 16], key : [[u8; 16]; 17] , rounds : usize) ->  [u8; 16]
    {  

        let mut result = input;
    
        for i in 1..=rounds   //rounds =8  
        {
            let add1= addition(result, key[2*i-2],  1);
             
            
            let exp= exponent(add1, 1);
           
            let add2  =addition(exp, key[2*i-1],  2);
            
            result = matrix_mul( add2, M);
           
        }
       
       result = addition(result, key[16], 1);
    result

    }
   
fn decrypt(ciphertext: [u8; 16], keys: [[u8; 16]; 17]) -> [u8; 16] {
    
    let mut result = substitution(ciphertext, keys[16], 1);

    for i in (1..=8).rev() {
        result = matrix_mul( result, M_INVERSE);
        result = substitution(result, keys[2*i-1], 2);
        result = exponent(result, 2);
        result = substitution(result, keys[2*i-2], 1);
    }
    result
}

 

fn rotate_left_3(x: u8) -> u8 {
    x.rotate_left(3)
}
fn safer_plus_key_schedule(user_key: [u8; 16], bias_word:[[u8; 16]; 32]) -> [[u8; 16]; 17] {
    
     let mut  subkeys = [[0u8; 16]; 17];
     let mut key_register = [0u8; 17];
     subkeys[0]=user_key;
     let mut byte_17 = 0;

     for i in 0..16 {

         byte_17 ^= user_key[i];
         
     }
      key_register[..16].copy_from_slice(&user_key);
      key_register[16] = byte_17;



      for i in  1.. 17
      {  

          for j in 0.. 17
           {
             key_register[j] = rotate_left_3(key_register[j]);      

           }
         
         for  k in 0 .. 16
         {
             subkeys[i][k] =key_register[(i+k) %17 ].wrapping_add( bias_word[i-1][k] ) ; 
         }
           

      }
      
    
    subkeys
  
    }

fn main() {
    let key =     [41, 35, 190, 132, 225, 108, 214, 174, 82, 144, 73, 241, 241, 187, 233, 235];

    let keys = safer_plus_key_schedule(key,BIASES );

    let plaintext = [ 179,166,219,60,135,12,62,153, 36,94,13,28,6,183,71,222];

    //let expected = [    224,31,182,10,12,255,84,70,127,13,89,249,9,57,165,220];

   
    let ciphertext = encrypt(plaintext, keys,8);
    for   i in 0..ciphertext.len() {
       print!("{} ", ciphertext[i]);
    }
    
         println!();
   
   let decrypted = decrypt(ciphertext, keys);
   for   i in 0..decrypted.len() {
    print!("{} ", decrypted[i]);
    }
  
}
  


    //233 166 206 51 185 63 102 219 182 97 142 174 194 229 144 52