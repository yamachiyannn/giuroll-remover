//! Runtime restoration support for the Giuroll-remover companion.
//!
//! This module restores only modifications that were registered by this
//! process. It deliberately does not unload giuroll.dll: a callback or a
//! trampoline may already be in flight when the entry point is restored.

use std::{
    collections::HashSet,
    mem::{size_of, zeroed},
    ptr::copy_nonoverlapping,
    slice,
    sync::Mutex,
};

use ilhook::x86::HookPoint;
use windows::{
    Win32::{
        System::{
            Diagnostics::Debug::FlushInstructionCache,
            Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS},
            Threading::GetCurrentProcess as GetCurrentProcessWin,
        },
    },
};

use winapi::{
    shared::{
        minwindef::FALSE,
        winerror::{ERROR_INVALID_PARAMETER, ERROR_NO_MORE_FILES},
    },
    um::{
        errhandlingapi::GetLastError,
        handleapi::{CloseHandle, INVALID_HANDLE_VALUE},
        processthreadsapi::{
            GetCurrentProcessId, GetCurrentThreadId, GetThreadContext, OpenThread, ResumeThread,
            SuspendThread,
        },
        tlhelp32::{
            CreateToolhelp32Snapshot, Thread32First, Thread32Next, THREADENTRY32,
            TH32CS_SNAPTHREAD,
        },
        winnt::{CONTEXT, CONTEXT_CONTROL, THREAD_GET_CONTEXT, THREAD_SUSPEND_RESUME},
    },
};

/// Public result values returned by `Giuroll_Disable`.
pub const DISABLE_OK: u32 = 0;
pub const DISABLE_NOT_ACTIVE: u32 = 1;
pub const DISABLE_UNSAFE_GAME_STATE: u32 = 2;
pub const DISABLE_THREAD_BUSY: u32 = 3;
pub const DISABLE_FOREIGN_PATCH: u32 = 4;
pub const DISABLE_RESTORE_FAILED: u32 = 5;

struct MemoryPatch {
    address: usize,
    original: Vec<u8>,
    installed: Vec<u8>,
    executable: bool,
    restored: bool,
}

enum AppliedChange {
    Hook(HookPoint),
    Memory(MemoryPatch),
}

static APPLIED_CHANGES: Mutex<Vec<AppliedChange>> = Mutex::new(Vec::new());

fn flush_code(address: usize, length: usize) {
    unsafe {
        let _ = FlushInstructionCache(
            GetCurrentProcessWin(),
            Some(address as *const _),
            length,
        );
    }
}

/// Register a hook immediately after it is installed.
pub fn register_hook(hook: HookPoint) {
    APPLIED_CHANGES
        .lock()
        .expect("Giuroll change registry was poisoned")
        .push(AppliedChange::Hook(hook));
}

/// Replace a value while recording the exact old and new bytes for restoration.
/// All current call sites use plain data, byte arrays, or function pointers.
pub unsafe fn tamper_memory<T: Copy>(dst: *mut T, src: T) -> T {
    let length = size_of::<T>();
    assert_ne!(length, 0, "zero-sized memory patches are not supported");

    let original = dst.read_unaligned();
    let original_bytes = slice::from_raw_parts(
        &original as *const T as *const u8,
        length,
    )
    .to_vec();
    let installed_bytes = slice::from_raw_parts(&src as *const T as *const u8, length).to_vec();
    let address = dst as usize;
    let mut old_protection = PAGE_PROTECTION_FLAGS(0);
    VirtualProtect(
        address as *const _,
        length,
        PAGE_EXECUTE_READWRITE,
        &mut old_protection,
    )
    .expect("VirtualProtect failed while applying a Giuroll patch");

    let executable = old_protection.0 & 0xF0 != 0;

    dst.write_unaligned(src);

    let mut ignored_protection = PAGE_PROTECTION_FLAGS(0);
    VirtualProtect(
        address as *const _,
        length,
        old_protection,
        &mut ignored_protection,
    )
    .expect("VirtualProtect failed while restoring protection after a Giuroll patch");

    if executable {
        flush_code(address, length);
    }

    APPLIED_CHANGES
        .lock()
        .expect("Giuroll change registry was poisoned")
        .push(AppliedChange::Memory(MemoryPatch {
            address,
            original: original_bytes,
            installed: installed_bytes,
            executable,
            restored: false,
        }));

    original
}

/// Change a 32-bit relative jump target and record the displacement bytes.
pub unsafe fn tamper_relative_target<T: Copy>(dst: *mut std::ffi::c_void, src: T) -> T {
    assert_eq!(size_of::<T>(), size_of::<usize>());
    let instruction = dst as *mut u8;
    let opcode = instruction.read_unaligned();
    // The opcode itself is not modified by Giuroll, but recording it makes
    // preflight detect another mod changing CALL/JMP into a different form.
    let _ = tamper_memory(instruction, opcode);

    let displacement = instruction.add(1) as *mut usize;
    let instruction_end = (dst as usize).wrapping_add(1 + size_of::<usize>());

    let old_target = instruction_end.wrapping_add(displacement.read_unaligned());
    let new_target: usize = std::mem::transmute_copy(&src);
    let new_displacement = new_target.wrapping_sub(instruction_end);
    let _old_displacement = tamper_memory(displacement, new_displacement);

    std::mem::transmute_copy(&old_target)
}

impl MemoryPatch {
    fn is_installed(&self) -> bool {
        if self.restored {
            return false;
        }
        unsafe {
            slice::from_raw_parts(self.address as *const u8, self.installed.len())
                == self.installed.as_slice()
        }
    }

    fn is_original(&self) -> bool {
        unsafe {
            slice::from_raw_parts(self.address as *const u8, self.original.len())
                == self.original.as_slice()
        }
    }

    fn code_range(&self) -> Option<(usize, usize)> {
        self.executable
            .then_some((self.address, self.installed.len()))
    }

    fn restore(&mut self) -> bool {
        if self.restored {
            return true;
        }

        let mut old_protection = PAGE_PROTECTION_FLAGS(0);
        let protect_result = unsafe {
            VirtualProtect(
                self.address as *const _,
                self.original.len(),
                PAGE_EXECUTE_READWRITE,
                &mut old_protection,
            )
        };
        if protect_result.is_err() {
            return false;
        }

        unsafe {
            copy_nonoverlapping(
                self.original.as_ptr(),
                self.address as *mut u8,
                self.original.len(),
            );
        }
        if self.executable {
            flush_code(self.address, self.original.len());
        }

        let mut ignored_protection = PAGE_PROTECTION_FLAGS(0);
        let restore_protection_result = unsafe {
            VirtualProtect(
                self.address as *const _,
                self.original.len(),
                old_protection,
                &mut ignored_protection,
            )
        };
        if restore_protection_result.is_err() {
            return false;
        }

        self.restored = true;
        true
    }
}

impl AppliedChange {
    fn code_range(&self) -> Option<(usize, usize)> {
        match self {
            Self::Hook(hook) => Some(hook.target_range()),
            Self::Memory(patch) => patch.code_range(),
        }
    }

    fn byte_len(&self) -> usize {
        match self {
            Self::Hook(hook) => hook.installed_bytes().len(),
            Self::Memory(patch) => patch.installed.len(),
        }
    }

    fn restore(&mut self) -> bool {
        match self {
            Self::Hook(hook) => {
                if hook.is_restored() {
                    return true;
                }
                if !hook.is_still_installed() {
                    return false;
                }
                let restored = unsafe { hook.unhook_in_place() };
                restored && hook.is_restored()
            }
            Self::Memory(patch) => {
                if patch.is_original() {
                    patch.restored = true;
                    return true;
                }
                if !patch.is_installed() {
                    return false;
                }
                patch.restore()
            }
        }
    }
}

struct Snapshot(winapi::um::winnt::HANDLE);

impl Drop for Snapshot {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

/// Holds every suspended game thread and resumes them on drop.
struct SuspendedThreads {
    handles: Vec<winapi::um::winnt::HANDLE>,
    thread_ids: HashSet<u32>,
    instruction_pointers: Vec<usize>,
    max_threads: usize,
}

impl SuspendedThreads {
    unsafe fn count_process_threads() -> Result<usize, ()> {
        let current_process = GetCurrentProcessId();
        let snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if snapshot_handle == INVALID_HANDLE_VALUE {
            return Err(());
        }
        let snapshot = Snapshot(snapshot_handle);
        let mut entry: THREADENTRY32 = zeroed();
        entry.dwSize = size_of::<THREADENTRY32>() as u32;
        if Thread32First(snapshot.0, &mut entry) == 0 {
            return Err(());
        }

        let mut count = 0usize;
        loop {
            if entry.th32OwnerProcessID == current_process {
                count = count.saturating_add(1);
            }
            if Thread32Next(snapshot.0, &mut entry) == 0 {
                if GetLastError() != ERROR_NO_MORE_FILES {
                    return Err(());
                }
                break;
            }
        }
        Ok(count)
    }

    unsafe fn suspend_all_except_current() -> Result<Self, ()> {
        let current_process = GetCurrentProcessId();
        let current_thread = GetCurrentThreadId();

        // Allocate before suspending anything. The extra capacity covers
        // threads created while the initial snapshot is being processed.
        // We refuse to continue if that reserve is exhausted, rather than
        // allocating while another game thread may hold the allocator lock.
        let initial_count = Self::count_process_threads()?;
        let max_threads = initial_count.saturating_add(256).max(256);
        let mut guard = Self {
            handles: Vec::with_capacity(max_threads),
            thread_ids: HashSet::with_capacity(max_threads),
            instruction_pointers: Vec::with_capacity(max_threads),
            max_threads,
        };
        guard.max_threads = guard
            .handles
            .capacity()
            .min(guard.thread_ids.capacity())
            .min(guard.instruction_pointers.capacity());

        // A single snapshot can miss a thread created just before its creator
        // is suspended. Repeat snapshots until an entire pass discovers no new
        // live game threads; once all known creators are suspended, the set is
        // stable. Abort rather than racing a process that keeps spawning threads.
        for _pass in 0..8 {
            let snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if snapshot_handle == INVALID_HANDLE_VALUE {
                return Err(());
            }
            let snapshot = Snapshot(snapshot_handle);
            let mut discovered = 0usize;

            let mut entry: THREADENTRY32 = zeroed();
            entry.dwSize = size_of::<THREADENTRY32>() as u32;
            if Thread32First(snapshot.0, &mut entry) == 0 {
                return Err(());
            }

            loop {
                let thread_id = entry.th32ThreadID;
                if entry.th32OwnerProcessID == current_process
                    && thread_id != current_thread
                    && !guard.thread_ids.contains(&thread_id)
                {
                    if guard.thread_ids.len() >= guard.max_threads {
                        return Err(());
                    }

                    let access = THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT;
                    let thread = OpenThread(access, FALSE, thread_id);
                    if thread.is_null() {
                        if GetLastError() != ERROR_INVALID_PARAMETER {
                            return Err(());
                        }
                    } else {
                        let suspend_count = SuspendThread(thread);
                        if suspend_count == u32::MAX {
                            let error = GetLastError();
                            CloseHandle(thread);
                            if error != ERROR_INVALID_PARAMETER {
                                return Err(());
                            }
                        } else {
                            guard.thread_ids.insert(thread_id);
                            guard.handles.push(thread);
                            discovered += 1;

                            let mut context: CONTEXT = zeroed();
                            context.ContextFlags = CONTEXT_CONTROL;
                            if GetThreadContext(thread, &mut context) == 0 {
                                return Err(());
                            }
                            guard.instruction_pointers.push(context.Eip as usize);
                        }
                    }
                }

                if Thread32Next(snapshot.0, &mut entry) == 0 {
                    if GetLastError() != ERROR_NO_MORE_FILES {
                        return Err(());
                    }
                    break;
                }
            }

            drop(snapshot);
            if discovered == 0 {
                return Ok(guard);
            }
        }

        Err(())
    }
}

impl Drop for SuspendedThreads {
    fn drop(&mut self) {
        unsafe {
            for thread in self.handles.drain(..).rev() {
                let _ = ResumeThread(thread);
                CloseHandle(thread);
            }
        }
    }
}

/// Check the complete change history as a virtual reverse-application. The
/// caller preallocates `virtual_bytes` before suspending game threads, so this
/// routine performs no heap allocations while the process is stopped.
fn preflight_reverse(changes: &[AppliedChange], virtual_bytes: &mut Vec<(usize, u8)>) -> bool {
    virtual_bytes.clear();

    for change in changes.iter().rev() {
        let (address, original, installed): (usize, &[u8], &[u8]) = match change {
            AppliedChange::Hook(hook) => (
                hook.target_range().0,
                hook.original_bytes(),
                hook.installed_bytes(),
            ),
            AppliedChange::Memory(patch) => (
                patch.address,
                patch.original.as_slice(),
                patch.installed.as_slice(),
            ),
        };

        if original.len() != installed.len() {
            return false;
        }

        for offset in 0..installed.len() {
            let byte_address = address + offset;
            let current = virtual_bytes
                .iter()
                .rev()
                .find(|(known_address, _)| *known_address == byte_address)
                .map(|(_, byte)| *byte)
                .unwrap_or_else(|| unsafe { *((byte_address) as *const u8) });
            if current != installed[offset] && current != original[offset] {
                return false;
            }
        }

        for (offset, byte) in original.iter().enumerate() {
            let byte_address = address + offset;
            if let Some((_, current_byte)) = virtual_bytes
                .iter_mut()
                .rev()
                .find(|(known_address, _)| *known_address == byte_address)
            {
                *current_byte = *byte;
            } else {
                // Capacity was reserved as the sum of all patch lengths.
                virtual_bytes.push((byte_address, *byte));
            }
        }
    }

    true
}

/// Restore all Giuroll modifications in reverse installation order.
///
/// The registry lock and every temporary allocation are acquired before
/// suspending threads. During the suspended transaction, no heap allocation or
/// deallocation is performed. If a thread is executing bytes being restored,
/// or any byte no longer matches our recorded patch history, restoration
/// aborts before the first write. The Giuroll module and trampoline allocations
/// intentionally remain resident, so a thread returning from one of them is
/// still valid.
pub fn restore_all_changes(is_idle: unsafe fn() -> bool) -> Result<(), u32> {
    let mut changes = APPLIED_CHANGES
        .lock()
        .map_err(|_| DISABLE_RESTORE_FAILED)?;
    if changes.is_empty() {
        return Err(DISABLE_NOT_ACTIVE);
    }

    let ranges = changes
        .iter()
        .filter_map(AppliedChange::code_range)
        .collect::<Vec<_>>();
    let total_patch_bytes = changes.iter().map(AppliedChange::byte_len).sum();
    let mut virtual_bytes = Vec::with_capacity(total_patch_bytes);

    // Only game-code ranges being overwritten need an instruction-pointer
    // check. The Giuroll DLL and trampoline buffers are deliberately retained.
    let suspended = unsafe { SuspendedThreads::suspend_all_except_current() }
        .map_err(|_| DISABLE_THREAD_BUSY)?;

    // Re-check the game state after every other game thread has stopped.
    if !unsafe { is_idle() } {
        return Err(DISABLE_UNSAFE_GAME_STATE);
    }

    for ip in &suspended.instruction_pointers {
        if ranges
            .iter()
            .any(|(start, length)| *ip >= *start && *ip < (*start).saturating_add(*length))
        {
            return Err(DISABLE_THREAD_BUSY);
        }
    }

    if !preflight_reverse(&changes, &mut virtual_bytes) {
        return Err(DISABLE_FOREIGN_PATCH);
    }

    for change in changes.iter_mut().rev() {
        if !change.restore() {
            return Err(DISABLE_RESTORE_FAILED);
        }
    }

    // The hook trampolines themselves were deliberately leaked by
    // HookPoint::unhook_in_place, so they remain valid for any thread that was
    // already returning through one. Once every game thread has resumed, the
    // bookkeeping can be discarded. This is essential for a later enable
    // cycle: keeping the old generation would make preflight mistake the
    // previous, already-restored patch for a foreign modification.
    drop(suspended);
    changes.clear();
    Ok(())
}
