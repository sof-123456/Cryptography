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

    // Pseudo-random generation algorithm (PRGA)
    let mut i = 0usize;
    let mut j = 0usize;

  //  for _ in 0..16 
  while  true  
  { // generate first 16 bytes as example
        i = (i + 1) % 256;
        j = (j + s[i] as usize) % 256;
        s.swap(i, j);
        let t_index = (s[i] as usize + s[j] as usize) % 256;
        let k = s[t_index];
        print!("{:02X} ", k); // print in hex
    }
    println!();
}

fn main() {
    let mut key = [0u8; 16];
    for i in 0..16 {
        key[i] = i as u8;
    }
    rc4(&key);
}


