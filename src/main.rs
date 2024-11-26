use std::env;

use fileproc::{files, processes};

fn main() -> Result<(), Box<dyn core::error::Error>> {
    // let file_path = env::args().skip(1).next().ok_or("no file provided")?;
    // let res = processes(&file_path)?;
    // println!("{:?}", res);
    let res = files(23972)?;
    res.iter().for_each(|p| {
        println!("{}", p.to_string_lossy())
    });
    Ok(())
}
