use std::io::{Cursor, Seek, SeekFrom, Write};
use std::slice;

#[cfg(windows)]
use core::ffi::c_void;

#[cfg(windows)]
use windows_sys::Win32::System::Memory::VirtualProtect;

#[cfg(windows)]
fn flush_instruction_cache(addr: usize, len: usize) {
    use std::ffi::c_void;
    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> *mut c_void;
        fn FlushInstructionCache(
            process: *mut c_void,
            base_address: *const c_void,
            size: usize,
        ) -> i32;
    }
    unsafe {
        let _ = FlushInstructionCache(GetCurrentProcess(), addr as *const c_void, len);
    }
}

#[cfg(not(windows))]
fn flush_instruction_cache(_addr: usize, _len: usize) {}

const JMP_INST_SIZE: usize = 5;

/// This is the routine used in a `jmp-back hook`, which means the EIP will jump back to the
/// original position after the routine has finished running.
///
/// # Arguments
///
/// * `regs` - The registers
/// * `user_data` - User data that was previously passed to [`Hooker::new`].
pub type JmpBackRoutine = unsafe extern "cdecl" fn(regs: *mut Registers, user_data: usize);

/// This is the routine used in a `function hook`, which means the routine will replace the
/// original function and the EIP will `retn` directly instead of jumping back.
/// Note that the address being hooked must be the start of a function.
///
/// # Parameters
///
/// * `regs` - The registers.
/// * `ori_func_ptr` - The original function pointer. Call this after converting it to the original function type.
/// * `user_data` - User data that was previously passed to [`Hooker::new`].
///
/// # Return value
///
/// Returns the new return value of the replaced function.
pub type RetnRoutine =
    unsafe extern "cdecl" fn(regs: *mut Registers, ori_func_ptr: usize, user_data: usize) -> usize;

/// This is the routine used in a `jmp-addr hook`, which means the EIP will jump to the specified
/// address after the routine has finished running.
///
/// # Parameters
///
/// * `regs` - The registers.
/// * `ori_func_ptr` - The original function pointer. Call this after converting it to the original function type.
/// * `user_data` - User data that was previously passed to [`Hooker::new`].
pub type JmpToAddrRoutine =
    unsafe extern "cdecl" fn(regs: *mut Registers, ori_func_ptr: usize, src_addr: usize);

/// This is the routine used in a `jmp-ret hook`, which means the EIP will jump to the return
/// value of the routine.
///
/// # Parameters
///
/// * `regs` - The registers.
/// * `ori_func_ptr` - The original function pointer. Call this after converting it to the original function type.
/// * `user_data` - User data that was previously passed to [`Hooker::new`].
///
/// # Return value
///
/// Returns the address you want to jump to.
pub type JmpToRetRoutine =
    unsafe extern "cdecl" fn(regs: *mut Registers, ori_func_ptr: usize, src_addr: usize) -> usize;

pub type JmpToRetEnumRoutine =
    unsafe extern "cdecl" fn(regs: *mut Registers, ori_func_ptr: usize, src_addr: usize) -> usize;

/// The hooking type.
pub enum HookType {
    /// Used in a jmp-back hook
    JmpBack(JmpBackRoutine),

    /// Used in a function hook. The first element is the mnemonic of the `retn`
    /// instruction.
    Retn(usize, RetnRoutine),

    /// Used in a jmp-addr hook. The first element is the destination address
    JmpToAddr(usize, u8, JmpToAddrRoutine),

    /// Used in a jmp-ret hook.
    JmpToRet(JmpToRetRoutine),

    JmpToEnumRet(Vec<usize>, JmpToRetEnumRoutine),
}

/// The common registers.
#[repr(C, packed(1))]
#[derive(Debug)]
pub struct Registers {
    /// The flags register.
    pub eflags: u32,
    /// The edi register.
    pub edi: u32,
    /// The esi register.
    pub esi: u32,
    /// The ebp register.
    pub ebp: u32,
    /// The esp register.
    pub esp: u32,
    /// The ebx register.
    pub ebx: u32,
    /// The edx register.
    pub edx: u32,
    /// The ecx register.
    pub ecx: u32,
    /// The eax register.
    pub eax: u32,
}

impl Registers {
    /// Get the value by the index from register `esp`.
    ///
    /// # Parameters
    ///
    /// * cnt - The index of the arguments.
    ///
    /// # Safety
    ///
    /// Process may crash if register `esp` does not point to a valid stack.
    #[must_use]
    pub unsafe fn get_arg(&self, cnt: usize) -> u32 {
        *((self.esp as usize + cnt * 4) as *mut u32)
    }
}

/// The trait which is called before and after the modifying of the `jmp` instruction.
/// Usually is used to suspend and resume all other threads, to avoid instruction colliding.
pub trait ThreadCallback {
    /// the callback before modifying `jmp` instruction, should return true if success.
    fn pre(&self) -> bool;
    /// the callback after modifying `jmp` instruction
    fn post(&self);
}

/// The entry struct in ilhook.
/// Please read the main doc to view usage.
pub struct Hooker {
    addr: usize,
    hook_type: HookType,

    user_data: usize,
}

/// The hook result returned by `Hooker::hook`.
pub struct HookPoint {
    addr: usize,
    // Keep the trampoline allocated after unhooking. A thread may already be
    // executing it when another thread restores the entry point.
    stub: Option<Box<[u8; 100]>>,
    stub_prot: u32,
    original: Box<[u8]>,
    installed: Box<[u8]>,
    active: bool,
}

#[cfg(not(target_arch = "x86"))]
fn env_lock() {
    panic!("This crate should only be used in arch x86_32!")
}
#[cfg(target_arch = "x86")]
fn env_lock() {}

impl Hooker {
    /// Create a new Hooker.
    ///
    /// # Parameters
    ///
    /// * `addr` - The being-hooked address.
    /// * `hook_type` - The hook type and callback routine.
    /// * `thread_cb` - The callbacks before and after hooking.
    /// * `flags` - Hook flags
    #[must_use]
    pub fn new(addr: usize, hook_type: HookType, user_data: usize) -> Self {
        env_lock();
        Self {
            addr,
            hook_type,

            user_data,
        }
    }

    /// Consumes self and execute hooking. Return the `HookPoint`.
    ///
    /// # Safety
    ///
    /// Process may crash (instead of panic!) if:
    ///
    /// 1. addr is not an accessible memory address, or is not long enough.
    /// 2. addr points to an incorrect position. (At the middle of an instruction, or where after it other instructions may jump to)
    /// 3. Wrong Retn-val if `hook_type` is `HookType::Retn`. i.e. A `cdecl` function with non-zero retn-val, or a `stdcall` function with wrong retn-val.
    /// 4. Set `NOT_MODIFY_MEMORY_PROTECT` where it should not be set.
    /// 5. hook or unhook from 2 or more threads at the same time without `HookFlags::NOT_MODIFY_MEMORY_PROTECT`. Because of memory protection colliding.
    /// 6. Other unpredictable errors.
    #[must_use]
    pub unsafe fn hook(self, len: usize) -> HookPoint {
        let origin = get_moving_insts(self.addr, len);
        let ol = origin.len() as u8;
        let stub = generate_stub(&self, origin.clone(), ol, self.user_data);
        let stub_prot = modify_mem_protect(stub.as_ptr() as usize, stub.len());

        let old_prot = modify_mem_protect(self.addr, JMP_INST_SIZE);
        modify_jmp_with_thread_cb(&self, stub.as_ptr() as usize);
        recover_mem_protect(self.addr, JMP_INST_SIZE, old_prot);
        flush_instruction_cache(self.addr, JMP_INST_SIZE);

        // Record the complete range that was examined by the hooker. The first
        // five bytes contain the jump; the remaining bytes must remain intact
        // before we are willing to restore the original sequence.
        let installed = unsafe {
            slice::from_raw_parts(self.addr as *const u8, origin.len()).to_vec()
        };

        HookPoint {
            addr: self.addr,
            stub: Some(stub),
            stub_prot,
            original: origin.into_boxed_slice(),
            installed: installed.into_boxed_slice(),
            active: true,
        }
    }
}

impl HookPoint {
    /// Consume self and restore the original instructions at the hook site.
    ///
    /// The trampoline is deliberately leaked after restoration. Another game
    /// thread may have entered it immediately before the entry-point jump was
    /// removed; releasing its memory here would make that in-flight call unsafe.
    pub unsafe fn unhook(mut self) {
        let _ = self.unhook_by_ref();
    }

    /// The address and size of the range overwritten by this hook.
    pub fn target_range(&self) -> (usize, usize) {
        (self.addr, self.installed.len())
    }

    /// Original bytes captured before installing the hook.
    pub fn original_bytes(&self) -> &[u8] {
        self.original.as_ref()
    }

    /// Bytes currently expected at the hook entry point.
    pub fn installed_bytes(&self) -> &[u8] {
        self.installed.as_ref()
    }

    /// Address range of the trampoline allocated for this hook.
    pub fn trampoline_range(&self) -> Option<(usize, usize)> {
        self.stub
            .as_ref()
            .map(|stub| (stub.as_ptr() as usize, stub.len()))
    }

    /// Whether the target still contains exactly the bytes installed by us.
    /// This prevents overwriting a later hook installed by another mod.
    pub fn is_still_installed(&self) -> bool {
        unsafe {
            slice::from_raw_parts(self.addr as *const u8, self.installed.len())
                == self.installed.as_ref()
        }
    }

    /// Whether the target already contains the original instruction bytes.
    pub fn is_restored(&self) -> bool {
        unsafe {
            slice::from_raw_parts(self.addr as *const u8, self.original.len())
                == self.original.as_ref()
        }
    }

    /// Restore the target without consuming the hook record.
    ///
    /// The trampoline allocation is intentionally retained even after this
    /// method succeeds, because a suspended thread may resume in that code.
    pub unsafe fn unhook_in_place(&mut self) -> bool {
        self.unhook_by_ref()
    }

    fn leak_trampoline(&mut self) {
        if let Some(stub) = self.stub.take() {
            // Keep the trampoline executable as well as allocated: another
            // thread may be part-way through it when this hook is removed.
            let _ = self.stub_prot;
            let _ = Box::leak(stub);
        }
    }

    #[cfg(windows)]
    fn unhook_by_ref(&mut self) -> bool {
        if !self.active {
            return true;
        }

        // Do not overwrite a hook installed after ours. Leak the trampoline
        // conservatively because an in-flight callback may still return to it.
        if !self.is_still_installed() {
            self.active = false;
            self.leak_trampoline();
            return false;
        }

        // This path runs while all other game threads are suspended. Avoid
        // assert!/panic and heap allocation: a panic while holding the game
        // stopped could leave the process deadlocked.
        let mut old_prot = 0u32;
        let changed = unsafe {
            VirtualProtect(
                self.addr as *const c_void,
                self.original.len(),
                0x40,
                &mut old_prot,
            )
        };
        if changed == 0 {
            return false;
        }

        unsafe {
            std::ptr::copy_nonoverlapping(
                self.original.as_ptr(),
                self.addr as *mut u8,
                self.original.len(),
            );
        }
        flush_instruction_cache(self.addr, self.original.len());

        let mut ignored_prot = 0u32;
        let protection_restored = unsafe {
            VirtualProtect(
                self.addr as *const c_void,
                self.original.len(),
                old_prot,
                &mut ignored_prot,
            ) != 0
        };

        self.active = false;
        self.leak_trampoline();
        protection_restored
    }

    #[cfg(unix)]
    fn unhook_by_ref(&mut self) -> bool {
        if !self.active {
            return true;
        }
        if !self.is_still_installed() {
            self.active = false;
            self.leak_trampoline();
            return false;
        }

        let old_prot = match modify_mem_protect(self.addr, self.original.len()) {
            Ok(protection) => protection,
            Err(_) => return false,
        };
        unsafe {
            std::ptr::copy_nonoverlapping(
                self.original.as_ptr(),
                self.addr as *mut u8,
                self.original.len(),
            );
        }
        recover_mem_protect(self.addr, self.original.len(), old_prot);
        self.active = false;
        self.leak_trampoline();
        true
    }
}

// When a HookPoint drops, it should restore the original code. The trampoline
// remains resident for the lifetime of the process to protect in-flight calls.
impl Drop for HookPoint {
    fn drop(&mut self) {
        let _ = self.unhook_by_ref();
    }
}

fn get_moving_insts(addr: usize, len: usize) -> Vec<u8> {
    let code_slice = unsafe { slice::from_raw_parts(addr as *const u8, len) };
    //let mut decoder = Decoder::new(32, code_slice, DecoderOptions::NONE);
    //decoder.set_ip(addr as u64);

    //code_slice[0..decoder.position()].into()
    code_slice.into()
}

#[cfg(windows)]
pub fn modify_mem_protect(addr: usize, len: usize) -> u32 {
    let mut old_prot: u32 = 0;
    let old_prot_ptr = std::ptr::addr_of_mut!(old_prot);
    // PAGE_EXECUTE_READWRITE = 0x40
    let ret = unsafe { VirtualProtect(addr as *const c_void, len, 0x40, old_prot_ptr) };
    assert_ne!(ret, 0, "VirtualProtect failed while changing hook memory protection");

    old_prot
}

#[cfg(unix)]
fn modify_mem_protect(addr: usize, len: usize) -> Result<u32, HookError> {
    let page_size = unsafe { sysconf(30) }; //_SC_PAGESIZE == 30
    if len > page_size.try_into().unwrap() {
        Err(HookError::InvalidParameter)
    } else {
        //(PROT_READ | PROT_WRITE | PROT_EXEC) == 7
        let ret = unsafe {
            mprotect(
                (addr & !(page_size as usize - 1)) as *mut c_void,
                page_size as usize,
                7,
            )
        };
        if ret != 0 {
            let err = unsafe { *(__errno_location()) };
            Err(HookError::MemoryProtect(err as u32))
        } else {
            // it's too complex to get the original memory protection
            Ok(7)
        }
    }
}

#[cfg(windows)]
pub fn recover_mem_protect(addr: usize, len: usize, old: u32) {
    let mut old_prot: u32 = 0;
    let old_prot_ptr = std::ptr::addr_of_mut!(old_prot);
    let ret = unsafe { VirtualProtect(addr as *const c_void, len, old, old_prot_ptr) };
    assert_ne!(ret, 0, "VirtualProtect failed while restoring hook memory protection");
}

#[cfg(unix)]
fn recover_mem_protect(addr: usize, _: usize, old: u32) {
    let page_size = unsafe { sysconf(30) }; //_SC_PAGESIZE == 30
    unsafe {
        mprotect(
            (addr & !(page_size as usize - 1)) as *mut c_void,
            page_size as usize,
            old as i32,
        )
    };
}

fn write_relative_off<T: Write + Seek>(buf: &mut T, base_addr: u32, dst_addr: u32) {
    let dst_addr = dst_addr as i32;
    let cur_pos = buf.stream_position().unwrap() as i32;
    let call_off = dst_addr - (base_addr as i32 + cur_pos + 4);
    buf.write(&call_off.to_le_bytes()).unwrap();
}

//fn move_code_to_addr(ori_insts: &Vec<u8>, dest_addr: u32) -> Vec<u8> {
//    let block = InstructionBlock::new(ori_insts, u64::from(dest_addr));
//    let encoded = BlockEncoder::encode(32, block, BlockEncoderOptions::NONE)
//        .map_err(|_| HookError::MoveCode)?;
//    Ok(encoded.code_buffer)
//}

fn write_ori_func_addr<T: Write + Seek>(buf: &mut T, ori_func_addr_off: u32, ori_func_off: u32) {
    let pos = buf.stream_position().unwrap();
    buf.seek(SeekFrom::Start(u64::from(ori_func_addr_off)))
        .unwrap();
    buf.write(&ori_func_off.to_le_bytes()).unwrap();
    buf.seek(SeekFrom::Start(pos)).unwrap();
}

fn generate_jmp_back_stub<T: Write + Seek>(
    buf: &mut T,
    stub_base_addr: u32,
    moving_code: &Vec<u8>,
    ori_addr: u32,
    cb: JmpBackRoutine,
    ori_len: u8,
    user_data: usize,
) {
    // push user_data
    buf.write(&[0x68]).unwrap();
    buf.write(&user_data.to_le_bytes()).unwrap();

    // push ebp (Registers)
    // call XXXX (dest addr)
    buf.write(&[0x55, 0xe8]).unwrap();
    write_relative_off(buf, stub_base_addr, cb as u32);

    // add esp, 0x8
    buf.write(&[0x83, 0xc4, 0x08]).unwrap();
    // popfd
    // popad
    buf.write(&[0x9d, 0x61]).unwrap();

    buf.write(&moving_code).unwrap();
    // jmp back
    buf.write(&[0xe9]).unwrap();

    write_relative_off(buf, stub_base_addr, ori_addr + u32::from(ori_len))
}

fn generate_retn_stub<T: Write + Seek>(
    buf: &mut T,
    stub_base_addr: u32,
    moving_code: &Vec<u8>,
    ori_addr: u32,
    retn_val: u16,
    cb: RetnRoutine,
    ori_len: u8,
    user_data: usize,
) {
    // push user_data
    buf.write(&[0x68]).unwrap();
    buf.write(&user_data.to_le_bytes()).unwrap();

    // push XXXX (original function addr)
    // push ebp (Registers)
    // call XXXX (dest addr)
    let ori_func_addr_off = buf.stream_position().unwrap() + 1;
    buf.write(&[0x68, 0, 0, 0, 0, 0x55, 0xe8]).unwrap();
    write_relative_off(buf, stub_base_addr, cb as u32);

    // add esp, 0xc
    buf.write(&[0x83, 0xc4, 0x0c]).unwrap();
    // mov [esp+20h], eax
    buf.write(&[0x89, 0x44, 0x24, 0x20]).unwrap();
    // popfd
    // popad
    buf.write(&[0x9d, 0x61]).unwrap();
    if retn_val == 0 {
        // retn
        buf.write(&[0xc3]).unwrap();
    } else {
        // retn XX
        buf.write(&[0xc2]).unwrap();
        buf.write(&retn_val.to_le_bytes()).unwrap();
    }
    let ori_func_off = buf.stream_position().unwrap() as u32;
    write_ori_func_addr(buf, ori_func_addr_off as u32, stub_base_addr + ori_func_off);

    buf.write(&moving_code).unwrap();

    // jmp ori_addr
    buf.write(&[0xe9]).unwrap();
    write_relative_off(buf, stub_base_addr, ori_addr + u32::from(ori_len))
}

fn generate_jmp_addr_stub<T: Write + Seek>(
    buf: &mut T,
    stub_base_addr: u32,
    moving_code: &Vec<u8>,
    ori_addr: u32,
    dest_addr: u32,
    cb: JmpToAddrRoutine,
    ori_len: u8,
    user_data: usize,
    popstack: u8,
) {
    // push user_data
    buf.write(&[0x68]).unwrap();
    buf.write(&user_data.to_le_bytes()).unwrap();

    // push XXXX (original function addr)
    // push ebp (Registers)
    // call XXXX (dest addr)
    let ori_func_addr_off = buf.stream_position().unwrap() + 1;
    buf.write(&[0x68, 0, 0, 0, 0, 0x55, 0xe8]).unwrap();
    write_relative_off(buf, stub_base_addr, cb as u32);

    // add esp, 0xc
    buf.write(&[0x83, 0xc4, 0x0c]).unwrap();
    // popfd
    // popad
    buf.write(&[0x9d, 0x61]).unwrap();

    //pop stack
    buf.write(&[0x83, 0xC4, popstack]).unwrap();
    // jmp back
    buf.write(&[0xe9]).unwrap();
    write_relative_off(
        buf,
        stub_base_addr,
        dest_addr, /* + u32::from(ori_len) */
    );

    let ori_func_off = buf.stream_position().unwrap() as u32;
    write_ori_func_addr(buf, ori_func_addr_off as u32, stub_base_addr + ori_func_off);

    buf.write(&moving_code).unwrap();

    // jmp ori_addr
    buf.write(&[0xe9]).unwrap();
    write_relative_off(buf, stub_base_addr, ori_addr + u32::from(ori_len))
}

fn generate_jmp_ret_stub<T: Write + Seek>(
    buf: &mut T,
    stub_base_addr: u32,
    moving_code: &Vec<u8>,
    ori_addr: u32,
    cb: JmpToRetRoutine,
    ori_len: u8,
    user_data: usize,
) {
    // push user_data
    buf.write(&[0x68]).unwrap();
    buf.write(&user_data.to_le_bytes()).unwrap();

    // push XXXX (original function addr)
    // push ebp (Registers)
    // call XXXX (dest addr)
    let ori_func_addr_off = buf.stream_position().unwrap() + 1;
    buf.write(&[0x68, 0, 0, 0, 0, 0x55, 0xe8]).unwrap();
    write_relative_off(buf, stub_base_addr, cb as u32);

    // add esp, 0xc
    buf.write(&[0x83, 0xc4, 0x0c]).unwrap();
    // mov [esp-4], eax
    buf.write(&[0x89, 0x44, 0x24, 0xfc]).unwrap();
    // popfd
    // popad
    buf.write(&[0x9d, 0x61]).unwrap();
    // jmp dword ptr [esp-0x28]
    buf.write(&[0xff, 0x64, 0x24, 0xd8]).unwrap();

    let ori_func_off = buf.stream_position().unwrap() as u32;
    write_ori_func_addr(buf, ori_func_addr_off as u32, stub_base_addr + ori_func_off);

    buf.write(&moving_code).unwrap();

    // jmp ori_addr
    buf.write(&[0xe9]).unwrap();
    write_relative_off(buf, stub_base_addr, ori_addr + u32::from(ori_len))
}

extern "C" fn panic_c() {
    panic!("Out of bounds of addresses array!");
}

fn generate_jmp_enum_ret_stub<T: Write + Seek>(
    buf: &mut T,
    stub_base_addr: u32,
    _moving_code: &Vec<u8>,
    _ori_addr: u32,
    cb: JmpToRetRoutine,
    _ori_len: u8,
    user_data: usize,
    rets: &[usize],
) {
    // push user_data
    buf.write(&[0x68]).unwrap();
    buf.write(&user_data.to_le_bytes()).unwrap();

    // push XXXX (original function addr)
    // push ebp (Registers)
    // call XXXX (dest addr)
    let ori_func_addr_off = buf.stream_position().unwrap() + 1;
    buf.write(&[0x68, 0, 0, 0, 0, 0x55, 0xe8]).unwrap();
    write_relative_off(buf, stub_base_addr, cb as u32);

    // add esp, 0xc
    buf.write(&[0x83, 0xc4, 0x0c]).unwrap();

    // cmp eax, rets.len()
    buf.write(&[0x3d]).unwrap();
    buf.write(&rets.len().to_le_bytes()).unwrap();
    // jb jump-to-address
    buf.write(&[0x72, 0x05]).unwrap();
    // jmp panic
    buf.write(&[0xe9]).unwrap();
    write_relative_off(buf, stub_base_addr, panic_c as extern "C" fn() as u32);
    // :jump-to-address
    // shl eax, 3
    buf.write(&[0xc1, 0xe0, 0x03]).unwrap();
    // add eax, a
    buf.write(&[0x05]).unwrap();
    let addr = stub_base_addr + buf.stream_position().unwrap() as u32 + 4 + 2;
    buf.write(&addr.to_le_bytes()).unwrap();
    // jmp eax
    buf.write(&[0xff, 0xe0]).unwrap();
    // :a
    for dst_addr in rets {
        // popfd
        // popad
        buf.write(&[0x9d, 0x61]).unwrap();
        // jmp back
        buf.write(&[0xe9]).unwrap();
        write_relative_off(buf, stub_base_addr, *dst_addr as u32);
        // nop
        buf.write(&[0x90]).unwrap();
    }

    let ori_func_off = buf.stream_position().unwrap() as u32;
    write_ori_func_addr(buf, ori_func_addr_off as u32, stub_base_addr + ori_func_off);
}

fn generate_stub(
    hooker: &Hooker,
    moving_code: Vec<u8>,
    ori_len: u8,
    user_data: usize,
) -> Box<[u8; 100]> {
    let mut raw_buffer = Box::new([0u8; 100]);
    let stub_addr = raw_buffer.as_ptr() as u32;
    let mut buf = Cursor::new(&mut raw_buffer[..]);

    // pushad
    // pushfd
    // mov ebp, esp
    buf.write(&[0x60, 0x9c, 0x8b, 0xec]).unwrap();

    match &hooker.hook_type {
        HookType::JmpBack(cb) => generate_jmp_back_stub(
            &mut buf,
            stub_addr,
            &moving_code,
            hooker.addr as u32,
            *cb,
            ori_len,
            user_data,
        ),
        HookType::Retn(val, cb) => generate_retn_stub(
            &mut buf,
            stub_addr,
            &moving_code,
            hooker.addr as u32,
            *val as u16,
            *cb,
            ori_len,
            user_data,
        ),
        HookType::JmpToAddr(dest, popstack, cb) => generate_jmp_addr_stub(
            &mut buf,
            stub_addr,
            &moving_code,
            hooker.addr as u32,
            *dest as u32,
            *cb,
            ori_len,
            user_data,
            *popstack,
        ),
        HookType::JmpToRet(cb) => generate_jmp_ret_stub(
            &mut buf,
            stub_addr,
            &moving_code,
            hooker.addr as u32,
            *cb,
            ori_len,
            user_data,
        ),
        HookType::JmpToEnumRet(addr, cb) => generate_jmp_enum_ret_stub(
            &mut buf,
            stub_addr,
            &moving_code,
            hooker.addr as u32,
            *cb,
            ori_len,
            user_data,
            addr.as_slice(),
        ),
    };

    raw_buffer
}

fn modify_jmp(dest_addr: usize, stub_addr: usize) {
    let buf = unsafe { slice::from_raw_parts_mut(dest_addr as *mut u8, JMP_INST_SIZE) };
    // jmp stub_addr
    buf[0] = 0xe9;
    let rel_off = stub_addr as i32 - (dest_addr as i32 + 5);
    buf[1..5].copy_from_slice(&rel_off.to_le_bytes());
}

fn modify_jmp_with_thread_cb(hook: &Hooker, stub_addr: usize) {
    modify_jmp(hook.addr, stub_addr)
}

#[cfg(target_arch = "x86")]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[cfg(test)]
    #[inline(never)]
    fn foo(x: u32) -> u32 {
        println!("original foo, x:{}", x);
        x * x
    }
    #[cfg(test)]
    unsafe extern "cdecl" fn on_foo(
        reg: *mut Registers,
        old_func: usize,
        user_data: usize,
    ) -> usize {
        let old_func = std::mem::transmute::<usize, fn(u32) -> u32>(old_func);
        old_func((*reg).get_arg(1)) as usize + user_data
    }

    #[test]
    fn test_hook_function_cdecl() {
        assert_eq!(foo(5), 25);
        let hooker = Hooker::new(
            foo as usize,
            HookType::Retn(0, on_foo),
            CallbackOption::None,
            100,
            HookFlags::empty(),
        );
        let info = unsafe { hooker.hook().unwrap() };
        assert_eq!(foo(5), 125);
        unsafe { info.unhook().unwrap() };
        assert_eq!(foo(5), 25);
    }

    #[cfg(test)]
    #[inline(never)]
    extern "stdcall" fn foo2(x: u32) -> u32 {
        println!("original foo, x:{}", x);
        x * x
    }
    #[cfg(test)]
    unsafe extern "cdecl" fn on_foo2(
        reg: *mut Registers,
        old_func: usize,
        user_data: usize,
    ) -> usize {
        let old_func = std::mem::transmute::<usize, extern "stdcall" fn(u32) -> u32>(old_func);
        old_func((*reg).get_arg(1)) as usize + user_data
    }
    #[test]
    fn test_hook_function_stdcall() {
        assert_eq!(foo2(5), 25);
        let hooker = Hooker::new(
            foo2 as usize,
            HookType::Retn(4, on_foo2),
            CallbackOption::None,
            100,
            HookFlags::empty(),
        );
        let info = unsafe { hooker.hook().unwrap() };
        assert_eq!(foo2(5), 125);
        unsafe { info.unhook().unwrap() };
        assert_eq!(foo2(5), 25);
    }
}
