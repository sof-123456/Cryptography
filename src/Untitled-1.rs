fn analyze_key(cipher: &str, key_len: usize) -> Vec<u8> {
    let mut key = Vec::new();

    for pos in 0..key_len {
        let mut group = String::new();

        for (i, c) in cipher.chars().enumerate() {
            if i % key_len == pos && c.is_ascii_lowercase() {
                group.push(c);
            }
        }

        let mut counts = [0usize; 26];
        for c in group.chars() {
            counts[(c as u8 - b'a') as usize] += 1;
        }

        let (max_index, _) = counts.iter().enumerate().max_by_key(|&(_, v)| v).unwrap();

        // Shift 1 adjustment: subtract 1 to match your matrix indexing
        let shift = (26 + max_index as i32 - ('e' as u8 - b'a') as i32) % 26;
        let row_index = if shift == 0 { 25 } else { (shift - 1) as u8 };

        key.push(row_index);
    }

    key
}
fn break_cipher(matrix: &Vec<Vec<char>>, cipher: &str, key_len: usize) -> String {
    let key = analyze_key(cipher, key_len);

    let mut output = String::new();
    for (i, c) in cipher.chars().enumerate() {
        let row = &matrix[key[i % key_len] as usize];
        let decrypted = decryption(&c.to_string(), row);
        output.push_str(&decrypted);
    }

    output
}

/*// Online Rust compiler to run Rust program online
// Print "Try programiz.pro" message
fn   encryption (input:&str , key:[char;26] ) -> String 
{
  let  replace  = input.to_lowercase().replace(&['(','’', ')', ',', '\"', '.', ';', ':', '\'', ' '][..], "");  

  let lower_input= replace.to_lowercase();
  let base = b'a';
  let  mut cypher = String::new();

for c in lower_input.chars().filter(|c| c.is_ascii_lowercase())  {   
    let  index =(c as u8  - base  ) as usize ;
    cypher.push(key[index]);
  }
    return  cypher 
     
      
}
/* 
fn encrypt_new(
    matrix: &Vec<Vec<char>>,
    key: [u8; 5],
    input: &str,
) -> String {
    let mut output = String::new();

    for (i, c) in input
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_lowercase())
        .enumerate()
    {
        let row_index = key[i % key.len()] as usize;

        let row: [char; 26] = matrix[row_index].try_into().unwrap();

        let encrypted = encryption(&c.to_string(), row);
        output.push_str(&encrypted);
    }

    output
}



fn   decryption (input:&str , key:[char;26] ) ->String 
{
   
 
  let base =   b'a';
  let mut plain_text = String::new();
  
  for  c in input.chars()
  {   
    if let Some(index) = key.iter().position(|&x|  x== c )
    {
            let letter = (base  + index as u8) as char ;   
            plain_text.push(letter);
   }
 
   
  }
    return plain_text 
     
      
}


fn frequency(s: &str, item: char) -> f32 {
    let s = s.replace(&['(','’', ')', ',', '\"', '.', ';', ':', '\'', ' '][..], "");  

    let size = s.len() as f32;
    let count = s.chars().filter(|&x| x == item).count() as f32;
    (count / size) * 100.0
}



fn get_frequency (cypher :  &str  )-> Vec<(char, f32)> {
 let mut result: Vec<(char, f32)> = Vec::new();
 let mut  seen : Vec<char> = vec![]; 
 for i in cypher.chars()
   {
      if !seen.contains(&i)
      {
         let k = frequency( cypher , i );
         result.push((i , k));
         seen.push(i);
     }
   }
   
    result.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

  return   result ;
   
}

fn get_mapping  ( letters_freq: [char; 26], input: Vec<(char, f32)>  ) ->Vec<(char, char)> 
{
   let mut map: Vec<(char, char)> = Vec::new();
   for (i, j)  in      input.iter().zip(letters_freq.iter())
   {
           map.push((i.0, *j) ) ;        
   }
    return map ;
}



fn  analyze ( map: Vec<(char, char)>  ,  text :   &str ) ->String  
{
   text.chars()
    .map(|c| {
       match map.iter().find( |&&(i,_)|  i==c ){
          Some(&(_ , plain)) => plain, 
          None => c
        }
    }).collect()
}

fn main() {
let key: [char; 26] = [
        'q','w','e','r','t','y','u','i','o','p',
        'a','s','d','f','g','h','j','k','l','z',
        'x','c','v','b','n','m'
    ];

let  input : &str= "I started my journey in the United Kingdom. The xperiences and stories that connect each of us in unexpected ways."
//let input: &str = "SSAXXX";
;

let cypher =encryption (input,key )  ;
let  plain_text = decryption(&cypher, key );

//println!("Encryption :{}",  cypher );
//println!("Decryption :{}", plain_text);
let _letters_by_freq: [char; 26] = [
    'e','t','a','o','i','n','s','h','r','d',
    'l','c','u','m','w','f','g','y','p','b',
    'v','k','j','x','q','z'
];
   //println! ("{:?}",analyze( 
    // get_mapping(_letters_by_freq,  get_frequency(&cypher )), &cypher)) ;


    // println!("{:?}", get_mapping(_letters_by_freq,  get_frequency(&cypher )));
    // print!("Frequency Analysis: {:?}" , get_frequency(&cypher ) ) ;
   println!("{:?}", encryption_new(create_matrix(), input) ) ;

}
fn encryption(input: &str, key: &[char]) -> String {
    let replace = input
        .to_lowercase()
        .replace(&['(','’', ')', ',', '\"', '.', ';', ':', '\'', ' '][..], "");

    let base = b'a';
    let mut cypher = String::new();

    for c in replace.chars().filter(|c| c.is_ascii_lowercase()) {
        let index = (c as u8 - base) as usize;
        cypher.push(key[index]);
    }

    cypher
}
 
fn create_matrix() -> Vec<Vec<char>> {
    let alphabet: Vec<char> = ('a'..='z').collect();
    let mut matrix = Vec::with_capacity(26);

    for shift in 0..26 { // include shift 0
        let mut row = Vec::with_capacity(26);
        for i in 0..26 {
            let shifted_index = (26 + i - shift) % 26;
            row.push(alphabet[shifted_index]);
        }
        matrix.push(row);
    }

    matrix
}

fn encrypt_new(matrix: &Vec<Vec<char>>, key: [u8; 5], input: &str) -> String {
    let mut output = String::new();

    for (i, c) in input
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_lowercase())
        .enumerate()
    {
        let row_index = key[i % key.len()] as usize;
        let row = &matrix[row_index]; // &[char]

        let encrypted = encryption(&c.to_string(), row);
        output.push_str(&encrypted);
    }

    output
}
*/
fn create_matrix() -> Vec<Vec<char>> {
    let alphabet: Vec<char> = ('a'..='z').collect();
    let mut matrix: Vec<Vec<char>> = Vec::with_capacity(26);

    for shift in 1..26 {
        let mut row: Vec<char> = Vec::with_capacity(26);

        for i in 0..26 {
            // RIGHT shift
            let shifted_index = (26 + i - shift) % 26;
            row.push(alphabet[shifted_index]);
        }

        matrix.push(row);
    }

    matrix
}
fn decryption(input: &str, key: &[char]) -> String {
    let base = b'a';
    let mut plain = String::new();

    for c in input.chars() {
        if let Some(index) = key.iter().position(|&x| x == c) {
            plain.push((base + index as u8) as char);
        } else {
            plain.push(c); // keep non-letters as is
        }
    }

    plain
}

fn decrypt_new(matrix: &Vec<Vec<char>>, key: [u8; 5], input: &str) -> String {
    let mut output = String::new();

    for (i, c) in input
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_lowercase())
        .enumerate()
    {
        let row_index = key[i % key.len()] as usize;
        let row = &matrix[row_index]; // &[char]
        let decrypted = decryption(&c.to_string(), row);
        output.push_str(&decrypted);
    }

    output
}


fn analyze_key(cipher: &str, key_len: usize) -> Vec<u8> {
    let mut key = Vec::new();

    for pos in 0..key_len {
        // collect letters for this key position
        let mut group = String::new();

        for (i, c) in cipher.chars().enumerate() {
            if i % key_len == pos && c.is_ascii_lowercase() {
                group.push(c);
            }
        }

        // count frequencies
        let mut counts = [0usize; 26];
        for c in group.chars() {
            counts[(c as u8 - b'a') as usize] += 1;
        }

        // most frequent letter
        let (max_index, _) = counts
            .iter()
            .enumerate()
            .max_by_key(|&(_, v)| v)
            .unwrap();

        // assume it maps from 'e'
        let shift =
            (26 + max_index as i32 - ('e' as u8 - b'a') as i32) % 26;

        key.push(shift as u8);
    }

    key
}
fn break_cipher(matrix: &Vec<Vec<char>>, cipher: &str, key_len: usize) -> String {
    let key = analyze_key(cipher, key_len);

    // convert shifts into rows
    let mut output = String::new();

    for (i, c) in cipher.chars().enumerate() {
        let row = &matrix[key[i % key_len] as usize];
        let decrypted = decryption(&c.to_string(), row);
        output.push_str(&decrypted);
    }

    output
}


fn main() {
    let matrix = create_matrix();
   // let key = [3, 1, 4, 1, 5];
   // let key = [3, 1, 4]; 

    let cypher = "rqfhdtrifgnupeecmxntnuqsstrusqswyyjazymtmeuvoanccoxyzymvyvahudncrjndmhrpucwkbustpukbdwqpgnfhkmzhyryyaqbwgppatukprvnyoysnyvobxbrecgmatuldpprusmzhqqmhyfzcborzfoswyvraiqrdlnhdujgvpgjapyeugedsfoswyvcoqtznqwljquctbkwiduzzgpphzthiucbpyfnhqkksqjnsgucpzwtxqjjukjgxlivvduswypjmqmxppfbhiqxupqvatubpptrhsuvxlfxdeinbcqoatuopqunusuqhzacouioppvrjgbzgrtjpzmdgctnaghmxlioyaczqpqjknksifgcouhcrjcbzoqqggcplemdgcvqlnuridkusqtbwggoskmhifkwzuwmxdklhzjotpuxueeekytrvginrawyhfyncqcwkpufgcgbwusjtbwyhfjgtbkomqhdcruchfyncqpnhduqimywhxbnurjnteudbcfflmhxplfvvejnurjnttqchjgnwkuxtqcwkmigxtgapzwdmntnzeyncujrsqjgtgtlvyfktvkxuewdcctjsxozengjyqtsdfcelfqjtlqwatubdjqdyavswchxnakshgfndtumsyamhiddsryxwmirtlinyeymdlgxmfxdifkakobzhqejydyzvcuovgdcifgvzqbutqqywaihicgjjteswctkvfxvtpghvgdfucnuviiadrjflduqprjnybengjamyqirtbdxatxzspgvhdazqjgohourplfkvfxvtpgncutdcrnhhznhdsucvejzgrclvzldgqccpadhurjnftqcqsvtuammlfajafxhhncaaustaytvvyumirjnfiuqtzqcodulppmjixuotpuxuejgtwyxbxttcbqdifucawjjcqmncbgalpqsifgbadqmvceqhzsdlfklotqchcvcoqccdupxwberxrgcvaddplqcoqhhcyvqpdtbayubjmhqxyinvrjgtucazmmqpgnfhksnbncwfaddddvqlymzhyaxbzwetjnxdavzqmwcaiumiwuncqdmdrvjsxmhifduhoabjpnrusxzxpcwkeczajialkvhtpanfqigxqpxzqmzhztxhpqmsdnjamdcwcjjktyfwajnlwrnccuqpejgxlnrwemdgcexuejzcrnhjacogcublpymimcwpyftscpcpdemxacupfchvfvjsyerizglhxbdsyojsushdsubtubdqsvqpevngcjnhpmzhfkpomdclcnumahltbcwkmjnccfovdqfdmfmlmbnurjnbsbhccubvrjgtjqfldfzgrqoouiepagjzbubxynolmjtgcqoatyrefabpawmdkafheyshbgjatbhzcrjsxeqlfklosqutrqcoqmgdjgvhzqmxlfnzohhqydufqczrgcclpqoeccahzsdxluypfunufkbomhcamqthztzirjnzmcdigonheeqimhyheihdlcclmdchsholdymvczyyqirxmpfousgsgfwvfxzgkqwpluvxrjqpeylesfnufizgacbausrbgnnhztjtcpblxvrprkbmuucqccapzwgtuqalmbzgegobdeqgyvqldqripclomdnkctlvmjvwgeqomtjtnvqpymzgkcuszyfwryqpxugxqpnpsxadstqhprdtlqksuwdsrqklmhswchdsxidkctrakeeppwbzuqmcmxntnuqcgiqaqdsxpgufgdogcrjyqtgxqyrkqiktcxnsqirbypcsqmhifcuhdwdryrnaaysifgbvdjnuanxhwemtqgnzgfncrtjcqbktpumbdymvrjndudstpoxufxrxlufpfpdgjcwkahmdpvqpfqknucbikdnbccwzmtzergmaajgtjqwnoekshqdyzuxiftxbsxqjqurhrhnbcamrgxmtlvxzffdictbighfifgflmhdgmhcouibamctdmiznmwwnrukamyjseenuydxbfjvtlvhzunngrynuforttgwfqqqhmhjnqikxejcskqadtgcoqchsbnnoqyfwrxnykvzxpyratqswgpyvudstbcwkhuqnjkpofsnamwalprdppfqpeuxtqynyqbzgegjuprkjccwktqcplkwaqdsamqthnetirjntkusifccoqqunczyyqirxmpfousghmonwqeoaccomuhlimdnhbubjjkjyujxpqynsxqrttkmlzsdddcwlbyktnvrjekaycecouiepagfhetdrgfnkxozejgjzmdsdlgovdqkarjjaduexlgmigjpjgvnjabnjpnnzeuwrcrcmahswceryoklhrcwjqjgprccatyrbmonufyslyuksguvxrjlvxtgtfgukmrtcbnntmtdjnqohzeksdcmlpihaijjupadgajrlrjgprcywmhdcrnhjadspgpnkmbkwgucymldajkwniqqspqklmdclmtnatybzqjxleqmsecraqhrwgufoabdpnrnhdqmrcdnpzwutpadudkrhgcwouiaayetomyqtbpnpsxadstruefdrrgmaturtnglbxyzggvrlexzkgppuajgxliklfjdgrqmvmdcprnnusjggcojywuclgvqatqsgsfnlzznnkgwaavswcfrzoelumtczavnifgazixhrfvqloelbmplsmirtquxvrjdcqjxdoekstgafeqhsfkbuqyfwzqdyduzsgnhhztswgurzmjgpuvxvrqmrwkopfxzszgnumxzgbhavejhccxnyfxnjejcpfmnjjfkleebdjfrufxddjflvgdsgwkelshnllsdpfunjrqoatuvpwqopfmgprdnlzqagmcmpekoemunfqiripcrntjegmobdujytpnjupmgtsiqtkwndbpnzejgtznjjwxzxpgmfakmvdgusamvwgucsqtzcbvqlzbzjejnkfxdrmpeldizigqwwdebtcfnkfxdgccmpzurhmhcoqvzxpjjpducnmwwnyqmxlvqlobnpivxhzivtpcustyrdnrxzujdcckponetgqsdlejhdlufheitgntrzudfwcunlyucimjjcqdnhsuypoyncmhjukylectcpzumrcqapzqoepqyyuqstlgbzudswchjjfeehseqxgurigqwznuhcerdafegxktnwxohcevxatulwcojkqamdupcvfxdxlsdpduqifccoqsdgrcruxogpbdnlzbnceckzqdsupqvygirxyoxyqjgplhxbdodppucomjgtfcmiqumhcpchnhnpbhxytyrwccuatjgprjnomtrjdhnyqtegmobvyuripcwnqddgtqdzyqkpbajrudcddgypxuohwyratsnctwuzuldhncbtexhhgpcldbnrsvxynkqhrqdaxqtvfkwneuutpcuaucdhyvqpeqmhugazmdcbmtnatqmttgadtumimvqlckdhrkxuixdifgaoqxzszgnuokqtbvqlbqsxcpcyqfkxcfwvfxdnbkmuajbjpgvltuxifcczujxdsucbyfdssrhvghldlghmahmdrjrusqmsugklxydkckwatertdgusamrwctnyqczgigmatuaayetomyqtbkwkulhsscuzmhbpqvrjmbkneqbwqbsgsvqzuhfdqrnsfhtifggjxqhbcfjuajgtprjzeumvctjztqaqgnhkdurhcfvhzeepzqdareqiwyqvxenzcfupwuzrjgarmdcemubleidsytnkzertypmhhuqnznxaoxxuyennaiotjvabfxzajvqlktnxqvxnqjgdjfxmakqvmqmygirxypvvzuxupgnndqsxqcwkreqcmvqpzwnwzwcfakqtowraqmqdliruyooppvrjgbzggpbamdbtqcrkfxdhukbzbqsxcpcxgydijaxmoetgqgrjmdsppidlfxdbyvcldrdrywbluamduqwskcxduplheuajrohkassdpijcqcdbmpnfmdcwcjjkhuqnjkcaxusdnchtkznjppnfnqbzzgbppurwyxrusaderonhfxhhmywljfdcqgfoubdifgalreqcccaskjvdwgjyemgnucbatuqtlqxuqukhcvxwmoedpaxbmijtbvqlnbzrijjpducdlgwvyhoptnrjtueuujxomtatcpbbbfngrkwnyuswctnkuucpaqdwxunuwgjyeqfdgyavfusdktbnqddgynnwmdbwgpjafxdigonztuhhyfrzfqmipguhfyutmhvpzuajruqlpyccmvjuemdgkaulfjdgypmzauutlvdhxbxxacvlnqbzypmdtuqtfcelketrmonaajgprkbdtuqtyornaymvrqbamohxpgjsxocdlvzbujdzlqffqjhqmvqatukxqvnuqhraywpoqtzvykwpekoemunfakqlfquleusjnkbpzjgprddupbdifgwheadsrjnmuhrigdnamdxifkwnujhhczlsmyltbvqlduccmunkbqrhcppldmhifggadultqccpevzrrkxumdcifccoqxzhntnjuethjkcaxuhcrjnsgwfpegehzjgdsiqvrsnjpunwaldgrarzzebggondqcthrtntqcatpvqhfyspnrnhducifccpfmzhgpmlqtzhrjnftqchstvpeucifghvgdfucnuvixzhrgwlpjnpborafxduyecdujglmpmldvtapgjkuddhqaxbdrtcbnnomirdkgrtbeqiyplltevttgajadsxlwnkfxdrjgarixdcrjnftqcaywpoqtswckamubkxryjzarrtpxjixuswyvcoqitqhglaavswckatuhswhqruqthcrjnsmkfwrgadtumwcujdfxdbjcdntymvdqaatetvfkmhdurpwkcpedniqvdmrucusnuvrvqxcfapoxrsmtjupbnjgumvdztsegoyacxdstlvejtbccwksqhictbzfykaghhvgszcyfmaaonjprxzeurhgqwzekbwyxjsgqaacravbuqiwcbhdukprkxuxyjtktbnqddgynnwmdbwgpcoqdxdstkbztktzglvyurpqkpuuvhrypcvnzdrrccvzsdifccpeeermwazqyenmwalmbknytnhdukprkelavlgqgyhzsgxlujupxzkcpxayqctynrafbdtptxyfxqdsiqdqbkpzunuounukkwkixhrfkbcqhxrmovvzjnwsojunuhceuxyeqxiftxbsxzimqubjkqxypcmmdbnmjhvgqqtpkpofqfpgpbhutswchjpdxzxpgmadqutjnnyreqxpgjsxozbynvvejvgmppdtumxqchztuzcbkjyqhdayvnkexdxqjjypbxppguhfyncyvjsxinagvcsqymuyecatqsxucbuajhcrjnsqqriqwawdyrtbvxomldcmcwziuqimohsqjstpknebubicfjzykbwfohvgiotlvhvghodqvjnqvnglqcoudfifgwoyonjytnjmdcxbjxdqldgypmatqsxqextyumsydultclgqgyhzsgxlqqfqizbmuclyymtlvyldincgmwvixdgyuovdcqeyxupoxdudyqvekoemtclponjgpbdujytpnjupyjcmyqpyjndyvulmisxdkcdmimxaquhuqmspgncujbwmhcomjmpkgjmudducnuvixdlyujupxzsyravbuqiwqomakqifqdzmdchmwuzudgxqfjfkurcgexsmyzcbtnlhysrfvqhfmzhfkbumcdplfcoqonjliolxbnljqxrqtdpppnzfbxplffpfxbjpkxzujxprvqlmbkzlqfpzwftlvulyqmlgvqatuqtbpxzq";

   // let cipher = encrypt_new(&matrix, key, input);
   // println!("{}", cipher);
   // println!("{}", decrypt_new(&matrix, key, &cipher));
    let _broken = break_cipher(&matrix, &cypher,  8 );
    println!("{}", _broken);
}


/* 
fn encryption(input: &str, key: &[char]) -> String {
    let replace = input
        .to_lowercase()
        .replace(&['(','’', ')', ',', '\"', '.', ';', ':', '\'', ' '][..], "");

    let base = b'a';
    let mut cypher = String::new();

    for c in replace.chars().filter(|c| c.is_ascii_lowercase()) {
        let index = (c as u8 - base) as usize;
        cypher.push(key[index]);
    }

    cypher
}


fn create_matrix() -> Vec<Vec<char>> {
    let alphabet: Vec<char> = ('a'..='z').collect();
    let mut matrix = Vec::with_capacity(26);

    // Rows: shift 1..25 (your requirement)
    for shift in 1..26 {
        let mut row = Vec::with_capacity(26);
        for i in 0..26 {
            let shifted_index = (26 + i - shift) % 26;
            row.push(alphabet[shifted_index]);
        }
        matrix.push(row);
    }

    matrix
}

fn encrypt_new(matrix: &Vec<Vec<char>>, key: [u8; 5], input: &str) -> String {
    let mut output = String::new();

    for (i, c) in input
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_lowercase())
        .enumerate()
    {
        let row_index = key[i % key.len()] as usize;
        let row = &matrix[row_index]; // &[char]

        let encrypted = encryption(&c.to_string(), row);
        output.push_str(&encrypted);
    }

    output
}

fn decryption(input: &str, key: &[char]) -> String {
    let base = b'a';
    let mut plain = String::new();

    for c in input.chars() {
        if let Some(index) = key.iter().position(|&x| x == c) {
            plain.push((base + index as u8) as char);
        } else {
            plain.push(c);
        }
    }

    plain
}

fn decrypt_new(matrix: &Vec<Vec<char>>, key: [u8; 5], input: &str) -> String {
    let mut output = String::new();

    for (i, c) in input
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_lowercase())
        .enumerate()
    {
        let row_index = key[i % key.len()] as usize;
        let row = &matrix[row_index];
        let decrypted = decryption(&c.to_string(), row);
        output.push_str(&decrypted);
    }

    output
}

// Adjusted analyze_key() for shift-1 matrix




fn main() {
    let matrix = create_matrix();
    let key = [3, 1, 4, 1, 5]; // example key
    let input = "hellohellohello";

    let cipher = encrypt_new(&matrix, key, input);
    println!("Cipher: {}", cipher);

    let decrypted = decrypt_new(&matrix, key, &cipher);
    println!("Decrypted: {}", decrypted);

    let broken = break_cipher(&matrix, &cipher, key.len());
    println!("Broken by analysis: {}", broken);
}
 
fn main() {
    let matrix = create_matrix();
    let key = [3, 1, 4, 1, 5]; // example key
    let input = "hellohellohello";

    let cipher = encrypt_new(&matrix, key, input);
    println!("Cipher: {}", cipher);

    let decrypted = decrypt_new(&matrix, key, &cipher);
    println!("Decrypted: {}", decrypted);

    let broken = break_cipher(&matrix, &cipher, key.len());
    println!("Broken by analysis: {}", broken);
}


    fn main() {
    let cipher = "cymdvtzcruhrtvoxeyicinbtxvyupkjkemhcxyqiejuysnsdlvyhqmdnjdhdmdvwdxhaqybkmdrtwnduuwrbaqhdmbdjimdwqwybedgxpwqjkibhcduugyahkjiybsbzuhhjonweuryupgqvwekjwfdrttrcjbxxhcsjzeivwvozmjopbudxtpopyfybahdxdxjonnqbwkjlougitpwlhheapwqqqhyafkilqfvbcyepuaxnyvxyupeyvlquhdxlrwtxbuwlqujpuzcqymcqzeomaycwlujjbhlewlfsdgsmzbychsvaqofdwilwquuwrfcryvtqycssxpqycbqlrmlaohhxkywsdjjhvvkrusqkkejwluaqshggbhbcsdvhpjquvauyndxhfuzcpyopuklryhjbffsjkmdzrqdljyjjxjsihzxxirjlhasexwejlefdxyvwcqqhtlpbuhwfpluugyfhcdxhhymoohhrjzckjlsdzwoquihaxgddpbvodxhqilnwugauhaiqqhcvbdeixxlvrqgwblnzohcuzjxtdwxpeohlrwlgzhhwipxxmkmblcrulvsvvzbhbyvwcwhruyjvbbefwnkhhhjvqklhxqrnxeqxxllybryhvodxhjenxejvmtlfruqhqfmkmqitafyfdwilwquuwyuxxurjjondxlvtjukivgqyasqjiimxedgxxlvcuozuzxzfrwyanoqfleaqohesjofohhcebwqvhpbvfcrrxxdnbuuejonbfrshshnhhwilmlewlxhmbupehrjlbhjqjncqqhrvcrmhvulesthrjshkdamebbdevxqycksrrllacqwmeurpjkioojnrxxauxgdzlohcdxlwfhadyfybhawepidacrubauynlewlhlvkhnersnzuuweubdxhcmvdvtxrtvdljhhbfqklhaeumohhhqacruvxhhwquflqulomkmsoqktvijaqocgsmuxzfrwyanderruhwyjkihpwkjkmhklvqvwshabydkuvodxhaqybkmueysfkofscwjxorruvodxhqmhbkorydnoobosmvokrryjafodwcileodqsjajvbzmjokvqfosbavyqkxhrbqqhitjvbjvufosuucufncxlwdvbomdwryxktdrtmukjdrtonrqglynqmxhiaixxuvlyzcryqpywbguuisvwcjdrjshmepthlbcugmdaxkdlqfbmodwmhvwssdpyavswkxqsvyiwfujjvbhhqtjvyfmebbcclpuiddxlwvvaoxhetdjcxlkxhwnmhpbmxbchhqumkjrrukoyhdkevmnudpemcruxkbpwoivsvaqobrauyykhwsvorcvdguhbzufmqsooqwyhlxpjkmiwqiilswuxwozeipccthejousahtqsuyhzlyjqqqyijvcruzlesnwqqedpwnuvghpkkrocutjmydxukjzfhehhwmulriwrdurjxpbrquhbvxuqqhqacruveclcscheivadeitqzbseqejljxtvyvmnbyqkueybuvwyvwgxlgxkrndrxxhaweqmplfsjklyzrwfxhuuccqugqzcssvqysnkdgoulwcuojihcsiimukkoqumdnqomrvuhukhjivbayhuejonbqvxhhlrqqsllamedxmormxketrnzjkmcdjbcdpburqxwaxpuoxlwdlrqxeskyqkteiuuxlblkukcyrhehaqovxpbznfuumjfxpquyizrkdqsllvluurynqduqxyynvoxrfynzquitorcmlhuzuouyiblbccdrjsngywlqsjbwhgqwndelxjonceuxemlvedoeuncuhwkwxxjuelluvuuwtbasdjxxlfsdwihtxxjkwyubgywduyukdgshuxbjkmjhuimdwrfwychedzjnqsxukcyjkibvwqsrptqxehqioaqbexkxydcilevyxwubhabqxuqxezczuwihzkehjxxlfoquihvodxlwssxkazeihhykqkvluvezebzxyvdfebcdmhrjfbsnrvjdnxjbwucnxohehzxpqjiisrqxwpohkylhxxlvstgpuonswkxllaivdmhdrdxdxxpwzelrjlmkdgzuyhvyjljjxvexvukkoquhxpboohwmlaobdvwljxtepkljxtkethwsdwidauyenervddjkicfndjkejonklbinwaoivmeufryflivvofhsfsnkvimhtcyrheflleblehpciqvausukihzyknxshsvhwoflpuwcssvyrqnmjkmimjmuzeiknmygitshkfoiqzjxjrrumxbqopjojdhhjyunnrxxgbrdufsbvdbbhwilgmusxvvadxhgyylecvxqulojkejhcdxlwcvvodwmjdjcroyudrdxfsbkqoxhpthkedgputjnuxtemjxeohvhmotvmbrqkdgouylryhjjojdqstqynxjocsvwdqlrukjvbkmiaaklhpbpwqmdvtyxludrtdxbuwlyjtcxriihwnwdmjlacxlwmoxvudtfljbqqguinsdjzuyheduyizrkdkmiiuksnlqpaotqiynqlexvyubzufxukcruviflleblehpcsuvlqcrxwqsjorxweijanbjrhehwnqwpuupdxuichauugayaqdxdxhbmouqnefvodwsvaqotlwsvvpeuxivoyjkihzfryfljonmepqeulvqvwuzbyeixuubrezgesmfuucihrnxlwdlrqxeskyaoqgmbfjxtwlyzrcqwlqdcyeiedjhsvlxxhmluhrqojbtivezcsdhzuycrexkxardmrybkkoirgesmsdwluvunsrydaaiyyiwyxgdtyyanykwsvaqomdcemrdmkejinoddfhvjnyvyfwxcubiizcbqlkxaobepwmpcjuupqumgxhywoviwrstunciwluiuksnlqpaotbskuppuopedfryvxblmkdgxxlwvqxkxlmdxhgeueohvejpxxfusslnnugxxlaoqgmdlbceixxlokyulqpaotbskupwqqmdaqososqrcyqqwmlakbolyzxzfrwyanxulkxixehvuklbdyrridjcixvfyrcyqkxlboupitaxrqyidvbeismspxxeiedfrwfhvjpwodfieyrxqsthvybydxuuncilrjonpqfxembeskuklbdyrriinsdjtkacyxlqhlyvolrwaxdxhqxlvkthodvfxjrxxlrxgxmhladxdxxllohweyuuixdhrlnxbrrwhkcuqxvyxwhxwipjweuijojxvryhfnkhvxxhcruketinodvidajlhretmxbxlwxljvjkxxhcruketzdpvhvukobepwetncjuednnxuuzebbwqoetfjuyqhemnzyoifzhgywlsvwfkowycncfdwczqsilrjlavefyjvalkuwjvddbdyworxwvillakbwmclbkjkmihwcmhvihwncrvuaqkdhzuyfruqxeaqogxiiarydzluaqohkixhmluhrsbaotwluwjdyhrjynzblituxdxhctpmxewgkynwukioaqkjvmjfxeiwycwnnkscebaweqiomxbdrxxpwqqqhmlkoblillrxjksiloobosmzqohhvutjbahhjonlbdgaojshhhyumsllhkhucqugqzcssdpbfpyisibaaejkwyypyisibaaejkinjukypithwyjkihwjcihrwlakikerirvogvuzbotpedvokrryjmxbjbaxvuyenitsruudgblauqqhfvbcuvwukjbugreznkdgellairosjjqivdgunxcfhpjyddxdpbaqoogsyzcywhxxvuneiskypyegvkzbsqqqeunivuiunakjlwqumpeureaqsdjsxiddoryhlzeywimyxxwlrcfykhwmsbukhlriajxshwqpmdxhwmpbcfdxylwdgxmuauieigebaculgquckhjyuaqocdxjlalufekznsaqsmvwvopcedwmqvirbcwogssaxbwdzutnweqiohwnxhlqkeohbpyacvuwsfhhwomskywooeesrkoilhuzqkllrwrnzjpiqaqsiradlgzuqwudqsbhxxlaovrvdljbbbxmvhoquwmohgqvxxlaodrsdlnvihxewjivrvovdkinitaqoroesrqkyuitvwodrqhwjfblgxlopmksxhmluhribyzeuxyupwuwluynnyhhqjxefoiemhoquwqnxsmusjlcycuwwlwohdpuwjxskmdhcdxhxytncxhmihmsiwedaaobdxycnyvpmdlkejvlukrndrxqubguuqosndjhvqumcehzuuceqopoplkchfqjtkdgaxlaoxdzufxesrquaxdxdxyzfruuiqtrqelrwaxcjdcypaoqopokxxjtyyanudraolcsrrxxaqoblwjlwohvpqbprugewhrxyvyfwxcubskyfreoiilceflwyucrqwfkumvuwluujcahhjonpyuwjpkojdroaqsdjmjpbonfpqpvotwluynndrwukykividnnbmlxxlgdhhquzjdyvjqjcseqedkcrqwluojcfuispxeiomjauoyqxxluewjewlekdwlebpreigebacusslladolwdvlbypimlveiwvutnwrhvjojdywefwnkhhhjojdywaqzrxthithbdxhcxhmckuqyznnjkiovdxwiibsxgxdwjlwotwsqkvsjwlumjmjzmjofydgihmdvhhetpwoivcebalkqhblqkivsclrwfrvjhwmuksmleohfsdarxkhhjonmbhvadqodwlufqktoeknqotwlupapyopyafkirfilafqepuaqkjwluzdlzhgjvodxhmhtrbjknepwotlrjonvqxkxanbmkidoncqzxxlvvqxkxpwqvrvjoxewkmthaoidcyarcdrxiadpvhhvbuveijhpnnhlgxzmyhdrtsxeyvheysetjivyxworyhjxcjxquhwnwdmjlaciwmbsrporyshwktgxefxehssizncilsdzbeskelhueqepuwayfhvjfjcquibhcseqpyrnwhvkuunbqoifhwmxlrjonxoryhidxtoirllychwqzrqdljyjjxjrfzlldqwsdjndxdxyzxpsryhznsvbskynkbocqynkhhpqarfurjcybofdrsorxidrtojfuqsjtjnudpyacvuhvhvadxusknqguopqibodfiemvsdgaxplryvzuyhmepqeucyxxqqukoyqkivacqbxxyxewkejvxvkayhpjxjiedjhyxbskhaohlkxajqqlrihrnjkivhrbxdmhlmdhdzusuohishpaoqopohvkbpsiafbeqkmonxyveozqoqqhyhaohhpqannikiyzqkhgpohaobdxyvwkjdpbzxvywxblrxvdgjaqkjlaqzwyjlrjonvudwjzdbfumilmdekellwyqqwmladepcblcduumueyoswithbwkflxthykvtuuciexvfvbdqjivvaxewlyupdxhrxthykdvujjxtlhxvfolhvqumdxdxyzlycpidkjlbhlctacusedjqsdrlolbkcrwjlvsdhrjwnbirryrwymkihhbpeuqhwjfblgxlopmksibyzeuxukhyklridrdphvbhwnynredqscwsehcvudwjposjzeiurmeoeyhwnhhilpcmxrjjojdddquhosdhjusuymkimhbkdglqkjzhrtuycieijebadxryihwnirybzrxxlwthhiuvryjxvqledkaouymjjqdxdxmhbryvrqtnkdgxxlhykqkvluvezpevtothehuncjocqumgywlsbasevmjfjdjkiqsuudrayupquqxblvkdzmjocruuituxcu"; 
    let key_len = 7; // assumed key length

    let matrix = create_matrix();

    // Analyze and guess the key
    let guessed_key = analyze_key(&cipher, key_len);
    println!("Guessed key (row indices): {:?}", guessed_key);

    // Decrypt the ciphertext using the guessed key
    let decrypted = break_cipher(&matrix, &cipher, key_len);
    println!("Decrypted text: {}", decrypted);
}

// Create a 26x26 matrix of shifted alphabets starting from shift 1
fn create_matrix() -> Vec<Vec<char>> {
    let alphabet: Vec<char> = ('a'..='z').collect();
    let mut matrix = Vec::with_capacity(26);

    for shift in 1..=26 { // 1-based shift
        let mut row = Vec::with_capacity(26);
        for i in 0..26 {
            let shifted_index = (26 + i - shift) % 26;
            row.push(alphabet[shifted_index]);
        }
        matrix.push(row);
    }

    matrix
}

// Analyze cipher text and guess the key
fn analyze_key(cipher: &str, key_len: usize) -> Vec<u8> {
    let mut key = Vec::new();

    for pos in 0..key_len {
        let mut group = String::new();

        for (i, c) in cipher.chars().enumerate() {
            if i % key_len == pos && c.is_ascii_lowercase() {
                group.push(c);
            }
        }

        let mut counts = [0usize; 26];
        for c in group.chars() {
            counts[(c as u8 - b'a') as usize] += 1;
        }

        let (max_index, _) = counts.iter().enumerate().max_by_key(|&(_, v)| v).unwrap();

        // Explicitly compare with 'e' (most common English letter)
        let shift = (26 + max_index as i32 - ('e' as u8 - b'a') as i32) % 26;
        key.push(shift as u8);
    }

    key
}


// Decrypt cipher text using guessed key
fn break_cipher(matrix: &Vec<Vec<char>>, cipher: &str, key_len: usize) -> String {
    let key = analyze_key(cipher, key_len);

    let mut output = String::new();
    for (i, c) in cipher.chars().enumerate() {
        let row = &matrix[key[i % key_len] as usize];
        if let Some(pos) = row.iter().position(|&x| x == c) {
            let letter = (b'a' + pos as u8) as char;
            output.push(letter);
        }
    }

    output
}



