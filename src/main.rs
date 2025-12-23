fn key_to_bits(key: u128) -> Vec<u8> {
    let mut bits = Vec::with_capacity(64);
    for i in (0..64).rev() {
        bits.push(((key >> i) & 1) as u8);
    }
    bits
}

fn  parity_drop(key :Vec<u8> ) -> Vec<u8> 
{
    let mut decreased = Vec::with_capacity(56);
    for  i  in 0..64
    {
        if (i + 1) % 8 != 0 

        {  
           decreased.push(key[i]);
        }
    }
     decreased 
}

fn split (key56 :Vec<u8>) -> (Vec<u8>, Vec<u8>)
{
      return (key56[..28].to_vec(), key56[28..].to_vec()); 
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
    let (mut left28, mut right28)  = split (key56) ;

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


fn main() {

let key : u128 = 0x22234512987ABB23 ;

println!("16 round Keys : {:?}", key_generator(key));


}