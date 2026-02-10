    mod tables;
    use std::result;

    use  tables::{EXP_TABLE, LOG_TABLE, M, KEYS, M_INVERSE};

    fn add (input : u8,  key : u8   ) -> u8
    {
      //  let  sum : u16 = input as u16 + key as u16;
       // return   (sum  & 0xFF) as u8;
          input.wrapping_add(key)

    }

     fn sub (input  : u8 , key : u8 )-> u8{
        input.wrapping_sub(key)
     } 
    fn  addition (input : [u8; 16] , key : [u8; 16],  key_round : usize ) -> [u8; 16]
    {
        let  mut sum_byte  =  [0u8; 16] ;

    for  i in 0 .. 16 
    {

            // let shift = 8 * (15 - i);
        //  let input_byte : u8 = ((input >> shift) & 0xFF) as u8;
            // let key_byte : u8 = ((key >> shift) & 0xFF) as u8;

        //  let  out_byte : u8;
            if key_round == 1 {
            
            if  (i % 4 ==0)  || (i % 4 == 3 )  
            {
                // out_byte=input_byte ^  key_byte ;
                sum_byte[i] =  input[i] ^  key[i] ;
            }
            else
            {
                    //  out_byte=   add(input_byte, key_byte) ;
                    sum_byte[i] =   add(input[i], key[i]) ;
            }
        }    
        else
        {
            if  (i % 4 ==0)  || (i % 4 == 3 )  
            {
                sum_byte[i] =   add(input[i], key[i]) ;

            }
            else
            {
                //  out_byte=  input_byte ^  key_byte ; 
                sum_byte[i] =  input[i] ^  key[i]  ;

            }
        }
                
                    // sum_byte |= (out_byte  as u128 ) << shift;


    }
    sum_byte
    }



fn substitution(input: [u8; 16], key: [u8; 16], key_round: usize) -> [u8; 16] {
    let mut result = [0u8; 16];
    for i in 0..16 {
        let is_xor_type = (i % 4 == 0) || (i % 4 == 3);
        if key_round == 1 {
            // Inverse of encrypt Round Key 1
            result[i] = if is_xor_type { input[i] ^ key[i] } else { input[i].wrapping_sub(key[i]) };
        } else {
            // Inverse of encrypt Round Key 2
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

            // let shift = 8 * (15 - i);
            //let input_byte : u8 = ((input >> shift) & 0xFF) as u8;

            let out_byte= if  (i % 4 ==0)  || (i % 4 == 3 )  
            {
                EXP_TABLE[input[i] as usize] 
            }
            else
            {
                LOG_TABLE[input[i] as usize] 
            };
                    //  exp_byte |= (out_byte  as u128 ) << shift;
                    exp_byte[i] = out_byte;

    }

}
else
{
    for  i in 0 .. 16 
    {

            // let shift = 8 * (15 - i);
            //let input_byte : u8 = ((input >> shift) & 0xFF) as u8;

            let out_byte= if  (i % 4 ==0)  || (i % 4 == 3 )  
            {
                LOG_TABLE[input[i] as usize] 
            }
            else
            {
                EXP_TABLE[input[i] as usize] 
            };
                    //  exp_byte |= (out_byte  as u128 ) << shift;
                    exp_byte[i] = out_byte;

    } 
}
    exp_byte
    }
fn matrix_mul(m: [[u8; 16]; 16], x: [u8; 16]) -> [u8; 16] {
    let mut result = [0u8; 16];
    for i in 0..16 { // 'i' is the row of the matrix
        let mut sum: u8 = 0;
        for j in 0..16 { // 'j' is the column of the matrix / index of input
            // Multiply and wrap at 256
            let term = m[i][j].wrapping_mul(x[j]);
            sum = sum.wrapping_add(term);
        }
        result[i] = sum;
    }
    result
}
    /* 
    fn  matrix_mul(m: [[u8;16];16], x: [u8;16]) -> [u8;16] {
        let mut res = [0u8;16];
        for i in 0..16 {
            let mut sum = 0u8;
            for j in 0..16 {
                sum ^= gf256_mul(m[i][j], x[j]); // XOR after GF(2^8) multiply
            }
            res[i] = sum;
        }
        res
    }

    // This is GF(2^8) multiplication in the SAFER+ field
    fn gf256_mul(a: u8, b: u8) -> u8 {
        let mut a = a;
        let mut b = b;
        let mut p = 0u8;
        for _ in 0..8 {
            if (b & 1) != 0 {
                p ^= a;
            }
            let hi_bit = a & 0x80;
            a <<= 1;
            if hi_bit != 0 {
                a ^= 0x1B; // AES irreducible poly for example
            }
            b >>= 1;
        }
        p
    }
*/

    use std::io::{self, Write};

    fn  encrypt (input : [u8; 16], key : [[u8; 16]; 17] , rounds : usize) ->  [u8; 16]
    {  
        let mut result = input;
    
        for i in 1..=rounds   //rounds =8  
        {
            let add1= addition(result, key[2*i-2],  1);
            

            let exp= exponent(add1, 1);
           
            let add2  =addition(exp, key[2*i-1],  2);
             
        //   let bytes =to_matrix(add2);
            result = matrix_mul(M, add2);
           
            //  result = bytes_to_u128(mixed);

              
        } 
         result = addition(result, key[16], 1);
    result

    }
fn decrypt(ciphertext: [u8; 16], keys: [[u8; 16]; 17]) -> [u8; 16] {
    // 1. Undo the final output transformation (Key 17 / index 16)
    // The final step of encryption was addition(..., 1), so we undo that.
    let mut result = substitution(ciphertext, keys[16], 1);

    for i in (1..=8).rev() {
        // 2. Undo Matrix (using M_INVERSE)
        result = matrix_mul(M_INVERSE, result);

        // 3. Undo Key Addition 2 (the one after S-box)
        result = substitution(result, keys[2*i-1], 2);

        // 4. Undo S-box (Order 2 swaps EXP and LOG)
        result = exponent(result, 2);

        // 5. Undo Key Addition 1 (the one before S-box)
        result = substitution(result, keys[2*i-2], 1);
    }
    result
}

/*
    fn decrypt(ciphertext : [u8; 16] , keys : [[u8; 16]; 17]  ) -> [u8; 16]
    {
        let mut result = substitution(ciphertext, keys[16], 2);

        for i in (1..=8).rev() 
        {
            let mixed = matrix_mul(M_INVERSE, result);
            let add2 = substitution(mixed, keys[2*i-1], 1);
            let exp = exponent(add2, 2);
            result = substitution(exp, keys[2*i-2], 1);
        }
        result
    }*/


    fn bytes_to_u128(x: [u8; 16]) -> u128 {
        let mut v = 0u128;
        for i in 0..16 {
            v |= (x[i] as u128) << (8 * (15 - i));
        }
        v
    }
    
    fn to_matrix(input : u128) -> [u8; 16]
    {
        let mut matrix = [0u8; 16];
        for i in 0..16 
        {
            let shift = 8 * (15 - i);
            matrix[i] = ((input >> shift) & 0xFF) as u8;
            
        }
        matrix
    }
    fn main() {
        // 16-byte plaintext
    let plaintext = [ 179,166,219,60,135,12,62,153, 36,94,13,28,6,183,71,222];

    let expected = [
        224,31,182,10,12,255,84,70,
        127,13,89,249,9,57,165,220
    ];
    let ciphertext = encrypt(plaintext, KEYS, 8);
    for   i in 0..ciphertext.len() {
        print!("{} ", ciphertext[i]);
    }
    
         println!();

     let decrypted = decrypt(ciphertext, KEYS);
     for   i in 0..decrypted.len() {
        print!("{} ", decrypted[i]);
     }
     
     println!();
 println!("{}" , sub(0, 1));
   
    //  let ciphertext = round(plaintext, key, 8);

    // println!("Plaintext : {:032X}", plaintext);
    // println!("Ciphertext: {:032X}", ciphertext);
    //println!("{:032x}", bytes_to_u128([41, 35, 190, 132, 225, 108, 214, 174, 82, 144, 73, 241, 241, 187, 233, 235]));
    }

