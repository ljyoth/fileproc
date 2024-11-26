use std::env;

use fileproc::{files, processes};

fn main() -> Result<(), Box<dyn core::error::Error>> {
    let file_path = env::args().skip(1).next().ok_or("no file provided")?;
    let processes = processes(&file_path)?;
    println!("processes: {:?}", processes);
    let files = files(23972)?;
    println!("files: {files:?}");
    Ok(())
}
