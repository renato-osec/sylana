use solana_sbpf::{
    aligned_memory::AlignedMemory,
    declare_builtin_function, ebpf,
    elf::Executable,
    error::StableResult,
    memory_region::{AccessType, MemoryMapping, MemoryRegion},
    program::{BuiltinFunctionDefinition, BuiltinProgram},
    verifier::RequisiteVerifier,
    vm::{CallFrame, Config, ContextObject, EbpfVm, ExecutionMode},
};
use std::{error::Error, fs, ptr::NonNull, sync::Arc};

struct RunContext {
    remaining: u64,
    mapping: NonNull<MemoryMapping>,
}

impl RunContext {
    fn new() -> Self {
        Self {
            remaining: 10_000_000,
            mapping: NonNull::dangling(),
        }
    }
}

impl ContextObject for RunContext {
    fn consume(&mut self, amount: u64) {
        self.remaining = self.remaining.saturating_sub(amount);
    }

    fn get_remaining(&self) -> u64 {
        self.remaining
    }

    fn active_mapping_ptr(&mut self) -> NonNull<MemoryMapping> {
        self.mapping
    }
}

declare_builtin_function!(
    DummySyscall,
    fn rust(
        _vm: &mut RunContext,
        _arg_a: u64,
        _arg_b: u64,
        _arg_c: u64,
        _arg_d: u64,
        _arg_e: u64,
    ) -> Result<u64, std::io::Error> {
        Ok(0)
    }
);

declare_builtin_function!(
    MemcpySyscall,
    fn rust(
        vm: &mut RunContext,
        dst: u64,
        src: u64,
        len: u64,
        _arg_d: u64,
        _arg_e: u64,
    ) -> Result<u64, std::io::Error> {
        let mapping = unsafe { vm.mapping.as_ref() };
        let dst = match mapping.map(AccessType::Store, dst, len) {
            StableResult::Ok(address) => address,
            StableResult::Err(error) => return Err(std::io::Error::other(format!("{error:?}"))),
        };
        let src = match mapping.map(AccessType::Load, src, len) {
            StableResult::Ok(address) => address,
            StableResult::Err(error) => return Err(std::io::Error::other(format!("{error:?}"))),
        };
        unsafe {
            std::ptr::copy_nonoverlapping(src as *const u8, dst as *mut u8, len as usize);
        }
        Ok(0)
    }
);

declare_builtin_function!(
    MemsetSyscall,
    fn rust(
        vm: &mut RunContext,
        dst: u64,
        byte: u64,
        len: u64,
        _arg_d: u64,
        _arg_e: u64,
    ) -> Result<u64, std::io::Error> {
        let mapping = unsafe { vm.mapping.as_ref() };
        let dst = match mapping.map(AccessType::Store, dst, len) {
            StableResult::Ok(address) => address,
            StableResult::Err(error) => return Err(std::io::Error::other(format!("{error:?}"))),
        };
        unsafe {
            std::ptr::write_bytes(dst as *mut u8, byte as u8, len as usize);
        }
        Ok(0)
    }
);

fn put_u64(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn add_account(buf: &mut Vec<u8>, key: u8, owner: u8, amount: u64) {
    buf.push(u8::MAX);
    buf.extend_from_slice(&[0, 1, 0]);
    buf.extend_from_slice(&[0; 4]);
    buf.extend_from_slice(&[key; 32]);
    buf.extend_from_slice(&[owner; 32]);
    put_u64(buf, 1);
    put_u64(buf, 8);
    put_u64(buf, amount);
    buf.resize(buf.len() + 10 * 1024, 0);
    let alignment = buf.len().next_multiple_of(8) - buf.len();
    buf.resize(buf.len() + alignment, 0);
    put_u64(buf, 0);
}

fn test_input() -> Vec<u8> {
    let mut input = Vec::with_capacity(32 * 1024);
    put_u64(&mut input, 3);
    add_account(&mut input, 0x11, 0x22, 0x1122_3344_5566_7788);
    add_account(&mut input, 0x33, 0x44, 0);
    add_account(&mut input, 0x55, 0x66, 0);
    put_u64(&mut input, 1);
    input.push(1);
    input.extend_from_slice(&[0x55; 32]);
    input
}

fn main() -> Result<(), Box<dyn Error>> {
    let path = std::env::args_os()
        .nth(1)
        .ok_or("usage: reference-run INPUT.so")?;
    let mut loader = BuiltinProgram::new_loader(Config {
        enable_register_tracing: true,
        ..Config::default()
    });
    for name in ["sol_log_", "abort"] {
        DummySyscall::register(&mut loader, name)?;
    }
    MemsetSyscall::register(&mut loader, "sol_memset_")?;
    MemcpySyscall::register(&mut loader, "sol_memcpy_")?;
    let loader = Arc::new(loader);
    let executable = Executable::<RunContext>::from_elf(&fs::read(path)?, loader.clone())?;
    executable.verify::<RequisiteVerifier>()?;

    let mut input = test_input();
    let mut stack =
        AlignedMemory::<{ ebpf::HOST_ALIGN }>::zero_filled(executable.get_config().stack_size());
    let stack_len = stack.len();
    let mut heap = AlignedMemory::<{ ebpf::HOST_ALIGN }>::zero_filled(32 * 1024);
    let regions = vec![
        executable.get_ro_region(),
        MemoryRegion::new(&mut stack, ebpf::MM_STACK_START),
        MemoryRegion::new(&mut heap, ebpf::MM_HEAP_START),
        MemoryRegion::new(&raw mut input[..], ebpf::MM_INPUT_START),
    ];
    let version = executable.get_sbpf_version();
    let mapping =
        Box::new(unsafe { MemoryMapping::new(regions, executable.get_config(), version)? });
    let mut context = RunContext::new();
    context.mapping = NonNull::from(Box::leak(mapping));
    let mut vm = EbpfVm::new(loader, version, &mut context, stack_len);
    vm.registers[1] = ebpf::MM_INPUT_START;
    let mut frames = vec![CallFrame::default(); executable.get_config().max_call_depth];
    let (instructions, result) =
        vm.execute_program(&executable, &mut ExecutionMode::Interpreted, &mut frames);
    let expected = 18_u64 << 32;
    println!("instructions={instructions}");
    println!("result={result:?}");
    for (label, pc) in [
        ("safe_handler", 79),
        ("owner_load", 96),
        ("owner_compare_branch", 98),
        ("illegal_owner_store", 153),
    ] {
        println!(
            "visited.{label}={}",
            vm.register_trace
                .iter()
                .any(|registers| registers[11] == pc)
        );
    }
    if !matches!(result, StableResult::Ok(value) if value == expected) {
        return Err(format!("expected IllegalOwner {expected:#018x}, got {result:?}").into());
    }
    Ok(())
}
