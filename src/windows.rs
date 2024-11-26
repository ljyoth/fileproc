use std::{
    os::windows::io::AsRawHandle,
    path::{Path, PathBuf},
};

use windows::{
    Wdk::{
        Foundation::{NtQueryObject, ObjectTypeInformation, OBJECT_INFORMATION_CLASS},
        Storage::FileSystem::{
            FileProcessIdsUsingFileInformation, NtDuplicateObject, NtQueryInformationFile,
        },
        System::{
            SystemInformation::{NtQuerySystemInformation, SYSTEM_INFORMATION_CLASS},
            SystemServices::FILE_PROCESS_IDS_USING_FILE_INFORMATION,
        },
    },
    Win32::{
        Foundation::{
            GetLastError, HANDLE, HMODULE, MAX_PATH, STATUS_INFO_LENGTH_MISMATCH, UNICODE_STRING,
        },
        Storage::FileSystem::{GetFinalPathNameByHandleW, FILE_NAME_NORMALIZED},
        System::{
            ProcessStatus::GetModuleFileNameExW,
            Threading::{
                GetCurrentProcess, OpenProcess, PROCESS_DUP_HANDLE, PROCESS_QUERY_INFORMATION,
                PROCESS_VM_READ,
            },
            WindowsProgramming::PUBLIC_OBJECT_TYPE_INFORMATION,
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

#[repr(C)]
#[derive(Debug)]
/// from https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/handle.htm
struct SYSTEM_HANDLE_INFORMATION {
    NumberOfHandles: usize,
    Handles: [SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX; 1],
}

#[repr(C)]
#[derive(Debug)]
// from https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/handle_table_entry.htm?ts=0,97
struct SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    UniqueProcessId: usize,
    CreatorBackTraceIndex: u16,
    ObjectTypeIndex: u16,
    HandleAttributes: u32,
    HandleValue: usize,
    Object: *mut std::ffi::c_void,
    GrantedAccess: u32,
}

#[repr(C)]
#[derive(Debug)]
/// from https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/handle_ex.htm
struct SYSTEM_HANDLE_INFORMATION_EX {
    NumberOfHandles: usize,
    Reserved: usize,
    Handles: [SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX; 1],
}

#[repr(C)]
#[derive(Debug)]
// from https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/handle_table_entry_ex.htm?ts=0,97
struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    Object: *mut std::ffi::c_void,
    UniqueProcessId: usize,
    HandleValue: usize,
    GrantedAccess: u32,
    CreatorBackTraceIndex: u16,
    ObjectTypeIndex: u16,
    HandleAttributes: u32,
    Reserved: u32,
}

pub fn files(pid: usize) -> Result<Vec<PathBuf>, Error> {
    const SYSTEM_HANDLE_INFORMATION: SYSTEM_INFORMATION_CLASS = SYSTEM_INFORMATION_CLASS(0x10);
    const SYSTEM_EXTENDED_HANDLE_INFORMATION: SYSTEM_INFORMATION_CLASS =
        SYSTEM_INFORMATION_CLASS(0x40);
    let mut buffer: Vec<u8> = Vec::with_capacity(size_of::<SYSTEM_HANDLE_INFORMATION_EX>());
    let handle_info = unsafe {
        loop {
            let mut length = u32::default();
            if let Err(err) = NtQuerySystemInformation(
                SYSTEM_EXTENDED_HANDLE_INFORMATION,
                buffer.as_mut_ptr() as _,
                buffer.len() as _,
                &mut length,
            )
            .ok()
            {
                if err.code() != STATUS_INFO_LENGTH_MISMATCH.to_hresult() {
                    break Err(err);
                }
                buffer.resize(length as usize, 0);
                dbg!(buffer.len());
            } else {
                let handle_info = buffer.as_ptr() as *const SYSTEM_HANDLE_INFORMATION_EX;
                break Ok(&*handle_info);
            }
        }
    }?;
    println!("{:?}", handle_info);
    let mut files = Vec::with_capacity(handle_info.NumberOfHandles);
    unsafe {
        let proc_handle = OpenProcess(PROCESS_DUP_HANDLE, false, pid as u32)?;

        let mut length = u32::default();
        let mut type_info_buf: Vec<u8> =
            Vec::with_capacity(size_of::<PUBLIC_OBJECT_TYPE_INFORMATION>());
        let mut path_buf: Vec<u16> = vec![0; MAX_PATH as usize];
        let mut ptr = &handle_info.Handles as *const SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;
        for _ in 0..handle_info.NumberOfHandles {
            let handle_entry = &*ptr;
            if handle_entry.UniqueProcessId == pid {
                let mut handle = HANDLE::default();
                if NtDuplicateObject(
                    proc_handle,
                    HANDLE(handle_entry.HandleValue as _),
                    GetCurrentProcess(),
                    Some(&mut handle),
                    0,
                    0,
                    0,
                )
                .is_ok()
                {
                    let object_type_info = loop {
                        if let Err(err) = NtQueryObject(
                            HANDLE(handle_entry.HandleValue as _),
                            ObjectTypeInformation,
                            Some(type_info_buf.as_mut_ptr() as _),
                            type_info_buf.len() as _,
                            Some(&mut length),
                        )
                        .ok()
                        {
                            if err.code() != STATUS_INFO_LENGTH_MISMATCH.to_hresult() {
                                break Err(err);
                            }
                            type_info_buf.resize(length as usize, 0);
                            dbg!(type_info_buf.len());
                        } else {
                            let object_type_info =
                                type_info_buf.as_ptr() as *const PUBLIC_OBJECT_TYPE_INFORMATION;
                            break Ok(&*object_type_info);
                        }
                    };
                    if let Ok(object_type_info) = object_type_info {
                        let type_name =
                            String::from_utf16_lossy(object_type_info.TypeName.Buffer.as_wide());
                        if type_name == "File" {
                            // let mut len = 0;
                            // const ObjectNameInformation: OBJECT_INFORMATION_CLASS =
                            //     OBJECT_INFORMATION_CLASS(1);
                            // NtQueryObject(
                            //     HANDLE(handle_entry.HandleValue as _),
                            //     ObjectNameInformation,
                            //     Some(buf.as_mut_ptr() as _),
                            //     buf.capacity() as _,
                            //     Some(&mut len),
                            // )
                            // .ok()?;
                            // let name = buf.as_ptr() as *const UNICODE_STRING;
                            // let name = String::from_utf16_lossy((*name).Buffer.as_wide());

                            let len = GetFinalPathNameByHandleW(
                                HANDLE(handle_entry.HandleValue as _),
                                &mut path_buf,
                                FILE_NAME_NORMALIZED,
                            );
                            // TODO: handle error
                            if GetLastError().is_ok() {
                                let name = String::from_utf16_lossy(&path_buf[0..len as usize]);
                                let path = PathBuf::from(&name[r#"\\?\"#.len()..]);
                                files.push(path);
                            }
                        }
                    }
                };
            }
            ptr = ptr.add(1);
        }
    };
    Ok(files)
}
