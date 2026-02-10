    mod tables;
    use std::result;

    use  tables::{EXP_TABLE, LOG_TABLE, M, KEYS, M_INVERSE};

    fn add (input : u8,  key : u8   ) -> u8
    {
      //  let  sum : u16 = input as u16 + key as u16;
       // return   (sum  & 0xFF) as u8;
          input.wrapping_add(key)

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

    fn  exponent (input : [u8; 16]) -> [u8; 16]
    {
        let  mut exp_byte = [0u8; 16] ;

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
    exp_byte
    }

    fn matrix_mul(m: [[u8; 16]; 16], x: [u8; 16]) -> [u8; 16] {
        let mut result = [0u8; 16];
        for i in 0..16 {
            let mut sum: u32 = 0;
            for j in 0..16 {
                sum += (m[i][j] as u32) * (x[j] as u32);
            }
            result[i] = (sum & 0xFF) as u8;
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

    fn round (input : [u8; 16], key : [[u8; 16]; 17] , rounds : usize) ->  [u8; 16]
    {  
        let mut result = input;
    
        for i in 1..=rounds   //rounds =8  
        {
            let add1= addition(result, key[2*i-2],  1);
            

            let exp= exponent(add1);
           
            let add2  =addition(exp, key[2*i-1],  2);
             
        //   let bytes =to_matrix(add2);
            result = matrix_mul(M, add2);
           
            //  result = bytes_to_u128(mixed);

              
        } 
    result

    }


    fn  encrypt(plaintext : [u8; 16] , keys : [[u8; 16]; 17]  ) -> [u8; 16]
    {
        let mut result = round(plaintext, keys, 8);
            result = addition(result, keys[16], 1);

    result

    }



    fn decrypt(ciphertext : [u8; 16] , keys : [[u8; 16]; 17]  ) -> [u8; 16]
    {
        let mut result = addition(ciphertext, keys[16], 1);

        for i in (1..=8).rev() 
        {
            let mixed = matrix_mul(M_INVERSE, result);
            let add2 = addition(mixed, keys[2*i-1], 2);
            let exp = exponent(add2);
            result = addition(exp, keys[2*i-2], 1);
        }
        result
    }


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
    let ciphertext = encrypt(plaintext, KEYS);
    for   i in 0..ciphertext.len() {
        print!("{} ", ciphertext[i]);
    }
    
         println!();

     let decrypted = decrypt(ciphertext, KEYS);
     for   i in 0..decrypted.len() {
        print!("{} ", decrypted[i]);
     }
     
     println!();

   
    //  let ciphertext = round(plaintext, key, 8);

    // println!("Plaintext : {:032X}", plaintext);
    // println!("Ciphertext: {:032X}", ciphertext);
    //println!("{:032x}", bytes_to_u128([41, 35, 190, 132, 225, 108, 214, 174, 82, 144, 73, 241, 241, 187, 233, 235]));
    }

