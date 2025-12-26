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

const PC1: [usize; 56] = [
    57,49,41,33,25,17,9,
    1,58,50,42,34,26,18,
    10,2,59,51,43,35,27,
    19,11,3,60,52,44,36,
    63,55,47,39,31,23,15,
    7,62,54,46,38,30,22,
    14,6,61,53,45,37,29,
    21,13,5,28,20,12,4
];

fn parity_drop(key: Vec<u8>) -> Vec<u8> {
    let mut permuted = Vec::with_capacity(56);
    for &i in PC1.iter() {
        permuted.push(key[i - 1]);
    }
    permuted
}

fn split (key56 :Vec<u8>, len :usize ) -> (Vec<u8>, Vec<u8>)
{
      return (key56[..len].to_vec(), key56[len..].to_vec()); 
}

const SHIFT_TABLE: [usize; 16]   = [1, 1, 2, 2,
                                    2, 2, 2, 2,
                                    1, 2, 2, 2,
                                    2, 2, 2, 1];
			
fn shift_left(key28: &mut Vec<u8>,  shift : usize) 
{
      
           for  _  in   0..shift
           {
                let  first = key28.remove(0) ;
                key28.push(first);
           }

  
}

const PC2: [usize; 48] = [
    14,17,11,24,1,5,3,28,
    15,6,21,10,23,19,12,4,
    26,8,16,7,27,20,13,2,
    41,52,31,37,47,55,30,40,
    51,45,33,48,44,49,39,56,
    34,53,46,42,50,36,29,32
];
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
    let    key56 = parity_drop(key_to_bits(key) ) ;
    let (mut left28, mut right28)  = split (key56, 28) ;

    for  i in 0..16
    {
       shift_left(&mut left28, SHIFT_TABLE[i]);
       shift_left(&mut right28,SHIFT_TABLE[i]);
    //   let left28_clone = left28.clone();
     //  let right28_clone =  right28.clone();
       keys.push(compression(&left28,&right28));
    
        
              
    }
     keys
}

fn   xor( key:  Vec<u8>, input: Vec<u8> ) -> Vec<u8>
{
        let  mut result   =   Vec::with_capacity(key.len()) ;
        for   (i, j)  in  key.iter().zip(input.iter())
            {     result.push(i ^ j);}      
                 
          result              
}

fn swapper (mut left32: Vec<u8>, mut right32:Vec<u8>) -> (Vec<u8>, Vec<u8>) 
{         
        let  tmp:Vec<u8> =left32;
        left32=right32;
        right32= tmp;
        
     (left32, right32)
}

const SBOX :[[[usize; 16]; 4]; 8]= [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
		[0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
		[4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
		[15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

		[[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
		[3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
		[0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
		[13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

		[[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
		[13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
		[13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
		[1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

		[[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
		[13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
		[10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
		[3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

		[[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
		[14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
		[4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
		[11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

		[[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
		[10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
		[9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
		[4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

		[[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
		[13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
		[1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
		[6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

		[[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
		[1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
		[7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
		[2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]];

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
const EXPD :[usize; 48] = [32, 1, 2, 3, 4, 5, 4, 5,
		6, 7, 8, 9, 8, 9, 10, 11,
		12, 13, 12, 13, 14, 15, 16, 17,
		16, 17, 18, 19, 20, 21, 20, 21,
		22, 23, 24, 25, 24, 25, 26, 27,
		28, 29, 28, 29, 30, 31, 32, 1];

fn permutation (input:Vec<u8>,  matrix:  &[usize])-> Vec<u8>
{
   
    let mut output = Vec::with_capacity(matrix.len());
    for &i in matrix.iter()
    {
        output.push(input[i-1]);
    }
    return output;
}
const PER :[usize; 32]= [16, 7, 20, 21,
	29, 12, 28, 17,
	1, 15, 23, 26,
	5, 18, 31, 10,
	2, 8, 24, 14,
	32, 27, 3, 9,
	19, 13, 30, 6,
	22, 11, 4, 25];


fn function(input32 :Vec<u8>,  key48 : Vec<u8>) -> Vec<u8>
{
  //let mut result = Vec::with_capacity(32);
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
      return swapper(l,r);
}
const INITIAL_PERM : [usize; 64] = [58, 50, 42, 34, 26, 18, 10, 2,
				60, 52, 44, 36, 28, 20, 12, 4,
				62, 54, 46, 38, 30, 22, 14, 6,
				64, 56, 48, 40, 32, 24, 16, 8,
				57, 49, 41, 33, 25, 17, 9, 1,
				59, 51, 43, 35, 27, 19, 11, 3,
				61, 53, 45, 37, 29, 21, 13, 5,
				63, 55, 47, 39, 31, 23, 15, 7];
const FINAL_PERM  :[usize;64]= [40, 8, 48, 16, 56, 24, 64, 32,
			39, 7, 47, 15, 55, 23, 63, 31,
			38, 6, 46, 14, 54, 22, 62, 30,
			37, 5, 45, 13, 53, 21, 61, 29,
			36, 4, 44, 12, 52, 20, 60, 28,
			35, 3, 43, 11, 51, 19, 59, 27,
			34, 2, 42, 10, 50, 18, 58, 26,
			33, 1, 41, 9, 49, 17, 57, 25];

fn encrypt(plaintext64 :Vec <u8>, key64 :u128) -> Vec<u8>
{
     let mut result = Vec::with_capacity(64);

     let perm_initial=permutation(plaintext64,&INITIAL_PERM);
     let (mut left32, mut right32)= split(perm_initial, 32);
      
  
     let keys = key_generator(key64);
     for   i     in   0..15
     {
        
        (left32, right32)=round(left32, right32, keys[i].clone());

     }
      left32 = xor(function(right32.clone(), keys[15].clone()), left32);
     result.extend(left32);
     result.extend(right32);
     
     result =permutation(result,&FINAL_PERM);
      result
     
}

fn decrypt(ciphertext64: Vec<u8>, key64: u128) -> Vec<u8> {
    // 1. Initial permutation
    let permuted = permutation(ciphertext64, &INITIAL_PERM);
    let (mut left32, mut right32) = split(permuted, 32);

    // 2. Generate keys
    let keys = key_generator(key64);

    // 3. Rounds 1..15 (in reverse)
    for i in (1..16).rev() {
        let (l, r) = mixer(left32.clone(), right32.clone(), keys[i].clone());
        left32 = r;  // swap
        right32 = l; // swap
    }

    // 4. 16th round (no swap)
    left32 = xor(function(right32.clone(), keys[0].clone()), left32);

    // 5. Concatenate halves
    let mut preoutput = Vec::with_capacity(64);
    preoutput.extend(left32);
    preoutput.extend(right32);

    // 6. Final permutation
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

fn encrypt_text(plaintext: &str, key: u128) -> Vec<u8> {
    let mut result = Vec::new();
    let bytes = plaintext.as_bytes();

    for chunk in bytes.chunks(8) {
        let mut block = [0u8; 8]; // DES block

        // zero padding
        for i in 0..chunk.len() {
            block[i] = chunk[i];
        }

        let block_bits = bytes_to_bits(&block);
        let encrypted = encrypt(block_bits, key);

        result.extend(encrypted);
    }

    result
}

fn main() {
    let plaintext: u128 = 0x123456ABCD132536;
    let key: u128 = 0x22234512987ABB23;

    //let ciphertext_bits = encrypt_text(plaintext, key);
    let cipher= encrypt( key_to_bits(plaintext), key);
    println!("Ciphertext (HEX): {}", key_bit_hex(&cipher));
        println!("plaintext (HEX): {}", key_bit_hex(&decrypt(cipher, key)));

}

 
 
