#![windows_subsystem = "windows"]
#![allow(non_snake_case)]

use std::{
    env,
    ffi::OsStr,
    mem::{size_of, transmute},
    os::windows::ffi::OsStrExt,
    path::PathBuf,
    ptr::null_mut,
};

use winapi::{
    shared::{minwindef::{DWORD, FALSE}, winerror::ERROR_NO_MORE_FILES},
    um::{
        errhandlingapi::GetLastError,
        handleapi::{CloseHandle, INVALID_HANDLE_VALUE},
        libloaderapi::{GetModuleHandleW, GetProcAddress},
        memoryapi::{VirtualAllocEx, VirtualFreeEx, WriteProcessMemory},
        minwinbase::LPTHREAD_START_ROUTINE,
        processthreadsapi::{CreateRemoteThread, GetExitCodeThread, OpenProcess},
        synchapi::WaitForSingleObject,
        tlhelp32::{
            CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32FirstW,
            Process32NextW, MODULEENTRY32W, PROCESSENTRY32W, TH32CS_SNAPMODULE,
            TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
        },
        winbase::INFINITE,
        winuser::{MessageBoxW, MB_ICONERROR, MB_OK},
        winnt::{
            MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, PROCESS_CREATE_THREAD,
            PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
        },
    },
};

struct OwnedHandle(winapi::um::winnt::HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe {
            if !self.0.is_null() {
                CloseHandle(self.0);
            }
        }
    }
}

fn process_id_by_name(expected: &str) -> Result<DWORD, String> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(format!(
                "プロセス一覧を取得できません (Win32 error {})",
                GetLastError()
            ));
        }
        let _snapshot = OwnedHandle(snapshot);

        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = size_of::<PROCESSENTRY32W>() as DWORD;
        if Process32FirstW(snapshot, &mut entry) == 0 {
            return Err(format!(
                "プロセス一覧を読み取れません (Win32 error {})",
                GetLastError()
            ));
        }

        let mut matches = Vec::new();
        loop {
            let name = String::from_utf16_lossy(
                &entry.szExeFile[..entry
                    .szExeFile
                    .iter()
                    .position(|c| *c == 0)
                    .unwrap_or(entry.szExeFile.len())],
            );
            if name.eq_ignore_ascii_case(expected) {
                matches.push(entry.th32ProcessID);
            }
            if Process32NextW(snapshot, &mut entry) == 0 {
                let error = GetLastError();
                if error != ERROR_NO_MORE_FILES {
                    return Err(format!("プロセス一覧の走査に失敗しました (Win32 error {error})"));
                }
                break;
            }
        }

        match matches.as_slice() {
            [] => Err("th123.exe が見つかりません。先に天則を起動してください。".to_string()),
            [pid] => Ok(*pid),
            _ => Err("th123.exe が複数起動しています。1つだけ起動して実行してください。".to_string()),
        }
    }
}

/// Return the loaded module containing a function address in the current process.
/// GetProcAddress may resolve a forwarded export into KernelBase.dll rather than
/// kernel32.dll, so the owner is discovered from the local module list.
fn local_module_containing(address: usize) -> Result<(String, usize), String> {
    unsafe {
        let pid = winapi::um::processthreadsapi::GetCurrentProcessId();
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(format!(
                "ローカルのモジュール一覧を取得できません (Win32 error {})",
                GetLastError()
            ));
        }
        let _snapshot = OwnedHandle(snapshot);
        let mut entry: MODULEENTRY32W = std::mem::zeroed();
        entry.dwSize = size_of::<MODULEENTRY32W>() as DWORD;
        if Module32FirstW(snapshot, &mut entry) == 0 {
            return Err(format!(
                "ローカルのモジュール一覧を読み取れません (Win32 error {})",
                GetLastError()
            ));
        }

        loop {
            let base = entry.modBaseAddr as usize;
            let end = base.saturating_add(entry.modBaseSize as usize);
            if address >= base && address < end {
                let name = String::from_utf16_lossy(
                    &entry.szModule[..entry
                        .szModule
                        .iter()
                        .position(|c| *c == 0)
                        .unwrap_or(entry.szModule.len())],
                );
                return Ok((name, base));
            }
            if Module32NextW(snapshot, &mut entry) == 0 {
                let error = GetLastError();
                if error != ERROR_NO_MORE_FILES {
                    return Err(format!("ローカルのモジュール一覧の走査に失敗しました (Win32 error {error})"));
                }
                break;
            }
        }
    }
    Err("LoadLibraryW の実装モジュールを特定できません。".to_string())
}

/// Find a module by its base filename in the target process.
fn remote_module_base(pid: DWORD, expected_name: &str) -> Result<usize, String> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(format!(
                "th123.exe のモジュール一覧を取得できません (Win32 error {})",
                GetLastError()
            ));
        }
        let _snapshot = OwnedHandle(snapshot);
        let mut entry: MODULEENTRY32W = std::mem::zeroed();
        entry.dwSize = size_of::<MODULEENTRY32W>() as DWORD;
        if Module32FirstW(snapshot, &mut entry) == 0 {
            return Err(format!(
                "th123.exe のモジュール一覧を読み取れません (Win32 error {})",
                GetLastError()
            ));
        }

        loop {
            let name = String::from_utf16_lossy(
                &entry.szModule[..entry
                    .szModule
                    .iter()
                    .position(|c| *c == 0)
                    .unwrap_or(entry.szModule.len())],
            );
            if name.eq_ignore_ascii_case(expected_name) {
                return Ok(entry.modBaseAddr as usize);
            }
            if Module32NextW(snapshot, &mut entry) == 0 {
                let error = GetLastError();
                if error != ERROR_NO_MORE_FILES {
                    return Err(format!("対象プロセスのモジュール一覧の走査に失敗しました (Win32 error {error})"));
                }
                break;
            }
        }
    }
    Err(format!(
        "th123.exe に {} が見つかりません。",
        expected_name
    ))
}

fn inject_dll(pid: DWORD, dll_path: &PathBuf) -> Result<(), String> {
    let dll_path_str = dll_path
        .to_str()
        .ok_or_else(|| "DLLのパスをUnicode文字列に変換できません。".to_string())?;
    let wide_path: Vec<u16> = OsStr::new(dll_path_str)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let byte_length = wide_path.len() * size_of::<u16>();

    unsafe {
        let access = PROCESS_CREATE_THREAD
            | PROCESS_QUERY_INFORMATION
            | PROCESS_VM_OPERATION
            | PROCESS_VM_WRITE
            | PROCESS_VM_READ;
        let process = OpenProcess(access, FALSE, pid);
        if process.is_null() {
            return Err(format!(
                "th123.exe を開けません (Win32 error {})",
                GetLastError()
            ));
        }
        let _process = OwnedHandle(process);

        let remote_path = VirtualAllocEx(
            process,
            null_mut(),
            byte_length,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if remote_path.is_null() {
            return Err(format!(
                "対象プロセスに一時メモリを確保できません (Win32 error {})",
                GetLastError()
            ));
        }

        let mut written = 0usize;
        if WriteProcessMemory(
            process,
            remote_path,
            wide_path.as_ptr() as *const _,
            byte_length,
            &mut written,
        ) == 0
            || written != byte_length
        {
            let error = GetLastError();
            VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
            return Err(format!("DLLパスを書き込めません (Win32 error {error})"));
        }

        let kernel32_name: Vec<u16> = "kernel32.dll"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let kernel32 = GetModuleHandleW(kernel32_name.as_ptr());
        if kernel32.is_null() {
            let error = GetLastError();
            VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
            return Err(format!("kernel32.dll を取得できません (Win32 error {error})"));
        }

        let load_library_name = b"LoadLibraryW\0";
        let load_library = GetProcAddress(kernel32, load_library_name.as_ptr() as *const i8);
        if load_library.is_null() {
            let error = GetLastError();
            VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
            return Err(format!("LoadLibraryW を取得できません (Win32 error {error})"));
        }

        // Use the function's actual owning module and RVA. Forwarded exports
        // can point outside kernel32.dll, and ASLR means the local absolute
        // address must never be assumed to be valid in th123.exe.
        let load_library_address: usize = transmute(load_library);
        let (owner_name, local_owner_base) =
            local_module_containing(load_library_address).map_err(|error| {
                VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
                error
            })?;
        let remote_owner_base = remote_module_base(pid, &owner_name).map_err(|error| {
            VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
            error
        })?;
        let load_library_rva = load_library_address - local_owner_base;
        let remote_load_library = remote_owner_base + load_library_rva;
        let load_library_thread: unsafe extern "system" fn(
            winapi::shared::minwindef::LPVOID,
        ) -> DWORD = transmute(remote_load_library);
        let start_routine: LPTHREAD_START_ROUTINE = Some(load_library_thread);
        let remote_thread = CreateRemoteThread(
            process,
            null_mut(),
            0,
            start_routine,
            remote_path,
            0,
            null_mut(),
        );
        if remote_thread.is_null() {
            let error = GetLastError();
            VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
            return Err(format!(
                "リムーバーをロードするスレッドを作成できません (Win32 error {error})"
            ));
        }
        let _remote_thread = OwnedHandle(remote_thread);

        let wait_result = WaitForSingleObject(remote_thread, INFINITE);
        if wait_result != 0 {
            // The remote thread may still be using remote_path. Do not free
            // that buffer when its termination could not be confirmed.
            return Err(format!(
                "DLLロードスレッドの完了を確認できません (Win32 error {})。安全のため対象プロセス内の一時メモリは解放していません。",
                GetLastError()
            ));
        }
        let mut module_handle: DWORD = 0;
        if GetExitCodeThread(remote_thread, &mut module_handle) == 0 {
            let error = GetLastError();
            VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
            return Err(format!("DLLのロード結果を取得できません (Win32 error {error})"));
        }

        VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
        if module_handle == 0 {
            return Err("リムーバーDLLのロードに失敗しました。".to_string());
        }
    }

    Ok(())
}

fn run() -> Result<(), String> {
    let pid = process_id_by_name("th123.exe")?;
    let executable = env::current_exe().map_err(|e| format!("実行ファイルの場所を取得できません: {e}"))?;
    let directory = executable
        .parent()
        .ok_or_else(|| "ローダーのフォルダーを取得できません。".to_string())?;
    let dll_path = directory.join("giuroll-remover.dll");

    if !dll_path.is_file() {
        return Err(format!(
            "{} が見つかりません。ローダーと同じフォルダーに置いてください。",
            dll_path.display()
        ));
    }

    inject_dll(pid, &dll_path)?;
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        let title: Vec<u16> = "Giuroll Remover - エラー".encode_utf16().chain(Some(0)).collect();
        let body: Vec<u16> = error.encode_utf16().chain(Some(0)).collect();
        unsafe {
            MessageBoxW(null_mut(), body.as_ptr(), title.as_ptr(), MB_OK | MB_ICONERROR);
        }
    }
}
