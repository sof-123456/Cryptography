use std::mem::swap;

fn rc4(key: &[u8]) {
    let keylen = key.len();

    // Initialize S and T arrays
    let mut s = [0u8; 256];
    let mut t = [0u8; 256];

    for i in 0..256 {
        s[i] = i as u8;
        t[i] = key[i % keylen];
    }

    
    // Key-scheduling algorithm (KSA)
    let mut j = 0usize;
    for i in 0..256 {
        j = (j + s[i] as usize + t[i] as usize) % 256;
        s.swap(i, j); // swap s[i] and s[j]
    }
        println!();

     for i in 0..255
    {
        print!("{} ", s[i]);  
    }

    // Pseudo-random generation algorithm (PRGA)
    let mut i = 0usize;
    let mut j = 0usize;
    println!();
        println!();


  for _ in 0..16 
  //while  true 
  { 
        i = (i + 1) % 256;
        j = (j + s[i] as usize) % 256;
        s.swap(i, j);
        let t_index = (s[i] as usize + s[j] as usize) % 256;
        let k = s[t_index];
        
    }
    println!();
}

fn main() {
    let mut key = [0u8; 256];
    // s=[2,1 , 0, 3 ....]
    key[0] =0;
    key[1] =0;
    key[2]= 253;
    key[4]=0 ;

       for k in 1..64 {
        // Use wrapping_sub or ensure the value is positive before casting to u8
        key[4*k    ] = (256 - (4*k-1) ) as u8;
        key[4*k + 1] = (256- (4* k )) as u8;
        key[4*k + 2] = (255  - (4* k +2   )) as u8;
        key[4*k + 3] = (256 -( 4*k )) as u8;
    }

    //  s = [0,1,,,,, 255 ]
    //key[0]=0;
   //key[1]= 0;
   //for i in 1..255 {
   //   // key[i] = i as u8;
   //  key[i+1] = (256   - i) as u8;   //  key[2] = 255 ....
   //} 
    for i in 0..255
    {
        print!("{} ", key[i]);  
    }
    rc4(&key);
}

