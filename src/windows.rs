use std::{
    os::windows::io::AsRawHandle,
    path::{Path, PathBuf},
};

use windows::{
    Wdk::{
        Storage::FileSystem::{FileProcessIdsUsingFileInformation, NtQueryInformationFile},
        System::{
            SystemInformation::NtQuerySystemInformation,
            SystemServices::FILE_PROCESS_IDS_USING_FILE_INFORMATION,
        },
    },
    Win32::{
        Foundation::{GetLastError, HANDLE, HMODULE, MAX_PATH, STATUS_INFO_LENGTH_MISMATCH},
        System::{
            ProcessStatus::GetModuleFileNameExW,
            Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
            WindowsProgramming::SYSTEM_PROCESS_INFORMATION,
            IO::IO_STATUS_BLOCK,
        },
    },
};

use crate::Process;

#[derive(Debug)]
pub enum Error {
    IO(std::io::Error),
    Windows(windows::core::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::IO(error) => write!(f, "{error}"),
            Error::Windows(error) => write!(f, "{error}"),
        }
    }
}

impl core::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::IO(value)
    }
}

impl From<windows::core::Error> for Error {
    fn from(value: windows::core::Error) -> Self {
        Self::Windows(value)
    }
}

pub fn processes<P: AsRef<Path>>(file: P) -> Result<Vec<Process>, Error> {
    let file = std::fs::File::open(file)?;
    let mut buffer: Vec<u8> =
        Vec::with_capacity(size_of::<FILE_PROCESS_IDS_USING_FILE_INFORMATION>());
    let process_ids = unsafe {
        loop {
            let mut io_status_block = IO_STATUS_BLOCK::default();
            // See https://stackoverflow.com/questions/47507578/winapi-get-the-process-which-has-specific-handle-of-a-file/47510579#47510579
            if let Err(err) = NtQueryInformationFile(
                HANDLE(file.as_raw_handle()),
                &mut io_status_block,
                buffer.as_mut_ptr() as _,
                buffer.capacity() as u32,
                FileProcessIdsUsingFileInformation,
            )
            .ok()
            {
                if err.code() != STATUS_INFO_LENGTH_MISMATCH.to_hresult() {
                    break Err(err);
                }
                buffer.resize(io_status_block.Information * size_of::<usize>(), 0);
            } else {
                let process_ids = buffer.as_ptr() as *const FILE_PROCESS_IDS_USING_FILE_INFORMATION;
                break Ok(&*process_ids);
            }
        }
    }?;
    let mut processes = Vec::with_capacity(process_ids.NumberOfProcessIdsInList as usize);
    unsafe {
        let mut ptr = &process_ids.ProcessIdList as *const usize;
        for _ in 0..process_ids.NumberOfProcessIdsInList {
            let id = *ptr;
            let handle = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                false,
                id as u32,
            )?;
            let mut buf = vec![0; MAX_PATH as usize];
            let len = GetModuleFileNameExW(handle, HMODULE::default(), &mut buf);
            GetLastError().ok()?;
            let name = String::from_utf16(&buf[0..len as usize]).unwrap();
            let path = PathBuf::from(name);

            // TODO: get window name?
            // let handle = GetWindowThreadProcessId(handle, handle);
            // let len = GetWindowTextW(handle, &mut buf);
            // println!("{:?}", GetLastError().ok());
            // println!("{}: {:?}", len, buf);

            processes.push(Process { id, path });
            ptr = ptr.add(1);
        }
    };
    Ok(processes)
}

// pub fn files() -> Result<Vec<PathBuf>, Error> {
//     unsafe { NtQuerySystemInformation(
//         filehandle,
//         iostatusblock,
//         fileinformation,
//         length,
//         SystemExtendedInformation,
//     ) };
//     SYSTEM_PROCESS_INFORMATION;
//     SYSTEM_HANDLE_INFORMATION
// }
