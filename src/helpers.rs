// use std::fs::File;
// use std::io::Read;
// use std::io::BufReader;

// use crate::result::Result;

// pub fn get_file_taste(path: &str) -> Result<Vec<u8>>{
//     let f = File::open(path)?;
//     let mut reader = BufReader::new(f);
//     let mut buf = vec![0u8; 8];
//     reader.read_exact(&mut buf)?;
//     Ok(buf)
// }
