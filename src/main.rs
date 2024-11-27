use std::env;

use fileproc::{files, find_process, processes};

fn main() -> Result<(), Box<dyn core::error::Error>> {
    let mut args = env::args().skip(1);
    let subcommand = args.next().ok_or("no subcommand provided")?;
    match subcommand.as_str() {
        "processes" => {
            let file_path = args.next().ok_or("no file provided")?;
            let processes = processes(&file_path)?;
            println!("processes: {:?}", processes);
        }
        "files" => {
            let process_name = args.next().ok_or("no file provided")?;
            let process = find_process(&process_name)?.ok_or("process not found")?;
            let files = files(process.id())?;
            println!("files: {files:?}");
        }
        _ => Err("invalid subcommand")?,
    }
    Ok(())
}
