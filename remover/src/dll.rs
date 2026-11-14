#![allow(non_snake_case)]

use std::{ffi::CString, mem::transmute, ptr::null_mut};

use winapi::{
    shared::minwindef::{BOOL, DWORD, HINSTANCE, LPVOID, TRUE},
    um::{
        handleapi::CloseHandle,
        libloaderapi::{
            DisableThreadLibraryCalls, FreeLibraryAndExitThread, GetModuleHandleW, GetProcAddress,
        },
        processthreadsapi::CreateThread,
        winnt::DLL_PROCESS_ATTACH,
        winuser::{MessageBoxW, MB_ICONERROR, MB_OK},
    },
};

const STATUS_OK: u32 = 0;
const STATUS_NOT_ACTIVE: u32 = 1;
const STATUS_UNSAFE_GAME_STATE: u32 = 2;
const STATUS_THREAD_BUSY: u32 = 3;
const STATUS_FOREIGN_PATCH: u32 = 4;
const STATUS_RESTORE_FAILED: u32 = 5;

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

unsafe fn show_result(status: u32) {
    // Successful disable is intentionally silent. Only failures need user
    // attention; no success text or compatibility claim is displayed.
    if status == STATUS_OK {
        return;
    }

    let (title, body) = match status {
        STATUS_NOT_ACTIVE => (
            "Giuroll Remover - 対象なし",
            "Giurollが初期化されていないか、すでに無効化されています。",
        ),
        STATUS_UNSAFE_GAME_STATE => (
            "Giuroll Remover - 実行できません",
            "対戦中、または安全に解除できるメニュー状態ではありません。対戦を終了してタイトル／メニューに戻ってから実行してください。",
        ),
        STATUS_THREAD_BUSY => (
            "Giuroll Remover - 再試行してください",
            "ゲームのスレッドを安全に停止できなかったか、復元対象のゲームコードを実行中です。しばらく待って、メニュー画面で再実行してください。",
        ),
        STATUS_FOREIGN_PATCH => (
            "Giuroll Remover - 競合を検出",
            "Giurollが変更した箇所を別のMODも変更しています。他のMODを上書きしないため復元を中止しました。天則を終了して再起動してください。",
        ),
        _ => (
            "Giuroll Remover - 復元失敗",
            "復元処理中にエラーが発生しました。状態が一部変更されている可能性があります。天則を終了して再起動してください。",
        ),
    };

    let title_w = wide(title);
    let body_w = wide(body);
    MessageBoxW(null_mut(), body_w.as_ptr(), title_w.as_ptr(), MB_OK | MB_ICONERROR);
}

// FreeLibraryAndExitThread is documented not to return. The winapi 0.3
// binding nevertheless has a unit return type, so provide an explicit abort
// fallback to make every call site diverge in the Rust type system.
unsafe fn exit_worker(module: HINSTANCE, code: DWORD) -> ! {
    FreeLibraryAndExitThread(module, code);
    std::process::abort();
}

unsafe extern "system" fn remover_worker(parameter: LPVOID) -> DWORD {
    let self_module = parameter as HINSTANCE;
    let giuroll_name = wide("giuroll.dll");
    let giuroll_module = GetModuleHandleW(giuroll_name.as_ptr());

    if giuroll_module.is_null() {
        show_result(STATUS_NOT_ACTIVE);
        exit_worker(self_module, 0);
    }

    let function_name = CString::new("Giuroll_Disable").unwrap();
    let function = GetProcAddress(giuroll_module, function_name.as_ptr());
    if function.is_null() {
        show_result(STATUS_NOT_ACTIVE);
        exit_worker(self_module, 0);
    }

    let disable: unsafe extern "C" fn() -> u32 = transmute(function);
    let status = disable();
    show_result(status);

    exit_worker(self_module, 0)
}

#[no_mangle]
pub unsafe extern "system" fn DllMain(
    module: HINSTANCE,
    reason: DWORD,
    _reserved: LPVOID,
) -> BOOL {
    if reason == DLL_PROCESS_ATTACH {
        DisableThreadLibraryCalls(module);
        let thread = CreateThread(
            null_mut(),
            0,
            Some(remover_worker),
            module as LPVOID,
            0,
            null_mut(),
        );
        if thread.is_null() {
            return 0;
        }
        CloseHandle(thread);
    }
    TRUE
}
