use std::env;

use fileproc::processes;

fn main() -> Result<(), Box<dyn core::error::Error>> {
    let file_path = env::args().skip(1).next().ok_or("no file provided")?;
    let res = processes(&file_path)?;
    println!("{:?}", res);
    Ok(())
}
