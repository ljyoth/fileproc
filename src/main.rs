use std::{env, path::Path};

use fileproc::{files, files_by_pid, find_processes_by_name, find_processes_by_path, processes};

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
            let process_path = Path::new(&process_name);
            let processes = if process_path.exists() {
                find_processes_by_path(process_path)
            } else {
                find_processes_by_name(&process_name)
            }?;
            for process in processes {
                let files = files_by_pid(process.id())?;
                // let files = files(&process)?;
                println!("process: {process:?} files: {files:?}");
            }
        }
        _ => Err("invalid subcommand")?,
    }
    Ok(())
}
