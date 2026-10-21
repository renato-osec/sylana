use solana_sbpf::{
    declare_builtin_function, ebpf,
    elf::Executable,
    elf_parser::{
        consts::{SHT_DYNSYM, SHT_SYMTAB, STT_FUNC},
        types::Elf64Shdr,
        Elf64,
    },
    memory_region::MemoryMapping,
    program::{BuiltinFunctionDefinition, BuiltinProgram, SBPFVersion},
    vm::{Config, ContextObject},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    error::Error,
    fs,
    path::PathBuf,
    ptr::NonNull,
    sync::Arc,
};

const REGISTER_COUNT: u8 = 10;
const SYMBOL_NAME_LENGTH_MAXIMUM: usize = 4096;

// SBPFv2 PQR opcodes collide with JMP32; remap to private one-byte opcodes so parsers don't misread control flow.
const CANONICAL_PQR_OPCODES: [(u8, u8); 24] = [
    (ebpf::LMUL32_IMM, 0x20),
    (ebpf::LMUL32_REG, 0x28),
    (ebpf::LMUL64_IMM, 0x30),
    (ebpf::LMUL64_REG, 0x38),
    (ebpf::UHMUL64_IMM, 0x40),
    (ebpf::UHMUL64_REG, 0x48),
    (ebpf::SHMUL64_IMM, 0x50),
    (ebpf::SHMUL64_REG, 0x58),
    (ebpf::UDIV32_IMM, 0x60),
    (ebpf::UDIV32_REG, 0x68),
    (ebpf::UDIV64_IMM, 0x70),
    (ebpf::UDIV64_REG, 0x78),
    (ebpf::UREM32_IMM, 0x80),
    (ebpf::UREM32_REG, 0x88),
    (ebpf::UREM64_IMM, 0x90),
    (ebpf::UREM64_REG, 0x98),
    (ebpf::SDIV32_IMM, 0xa0),
    (ebpf::SDIV32_REG, 0xa8),
    (ebpf::SDIV64_IMM, 0xb0),
    (ebpf::SDIV64_REG, 0xb8),
    (ebpf::SREM32_IMM, 0xc0),
    (ebpf::SREM32_REG, 0xc8),
    (ebpf::SREM64_IMM, 0xd0),
    (ebpf::SREM64_REG, 0xd8),
];

fn usage() -> &'static str {
    "usage: sbpf-normalize INPUT.so OUTPUT.bin [--function-pc PC] [--summarize-log-formats] [--record-calls-to PC]"
}

fn version_number(version: SBPFVersion) -> Option<u8> {
    match version {
        SBPFVersion::V0 => Some(0),
        SBPFVersion::V1 => Some(1),
        SBPFVersion::V2 => Some(2),
        _ => None,
    }
}

fn bounded_string_in_section<'a>(
    elf_bytes: &'a [u8],
    section: &Elf64Shdr,
    offset: u32,
) -> Option<&'a [u8]> {
    let section_start = usize::try_from(section.sh_offset).ok()?;
    let section_size = usize::try_from(section.sh_size).ok()?;
    let start = section_start.checked_add(usize::try_from(offset).ok()?)?;
    let end = section_start.checked_add(section_size)?;
    let bytes = elf_bytes.get(start..end)?;
    let length = bytes.iter().position(|byte| *byte == 0)?;
    (length <= SYMBOL_NAME_LENGTH_MAXIMUM).then(|| &bytes[..length])
}

fn prefer_function_label(candidate: &str, current: &str) -> bool {
    let candidate_is_mangled = candidate.starts_with("_Z") || candidate.starts_with("_R");
    let current_is_mangled = current.starts_with("_Z") || current.starts_with("_R");
    (current_is_mangled && !candidate_is_mangled)
        || (candidate_is_mangled == current_is_mangled && candidate.len() < current.len())
}

// solana-sbpf 0.21.1 rejects names at exactly its 64-byte max (bounded scan omits the NUL); read labels ourselves.
fn elf_function_labels(elf_bytes: &[u8]) -> Result<BTreeMap<usize, String>, Box<dyn Error>> {
    let elf = Elf64::parse(elf_bytes)?;
    let sections = elf.section_header_table();
    let text = sections
        .iter()
        .find(|section| elf.section_name(section.sh_name).ok() == Some(b".text"))
        .ok_or("ELF has no .text section")?;
    let text_end = text
        .sh_addr
        .checked_add(text.sh_size)
        .ok_or("ELF .text address overflow")?;
    let mut labels = BTreeMap::<usize, String>::new();

    for symbol_section in sections
        .iter()
        .filter(|section| section.sh_type == SHT_SYMTAB || section.sh_type == SHT_DYNSYM)
    {
        let Some(string_section) = sections.get(symbol_section.sh_link as usize) else {
            continue;
        };
        let symbols = elf.get_symbol_table_of_section(symbol_section)?;
        for symbol in symbols {
            if symbol.st_info & 0x0f != STT_FUNC
                || symbol.st_value < text.sh_addr
                || symbol.st_value >= text_end
            {
                continue;
            }
            let relative = symbol.st_value - text.sh_addr;
            if relative % ebpf::INSN_SIZE as u64 != 0 {
                continue;
            }
            let Some(name) = bounded_string_in_section(elf_bytes, string_section, symbol.st_name)
            else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            let pc = usize::try_from(relative / ebpf::INSN_SIZE as u64)?;
            let candidate = String::from_utf8_lossy(name).into_owned();
            labels
                .entry(pc)
                .and_modify(|current| {
                    if prefer_function_label(&candidate, current) {
                        current.clone_from(&candidate);
                    }
                })
                .or_insert(candidate);
        }
    }
    Ok(labels)
}

// SBPFv2 reuses ALU classes for load/store and puts CALL_REG's register in src; translate only those encodings.
fn canonicalize_encoding(mut insn: ebpf::Insn, version: SBPFVersion) -> ebpf::Insn {
    if version != SBPFVersion::V2 {
        return insn;
    }
    insn.opc = match insn.opc {
        ebpf::LD_1B_REG => ebpf::LD_B_REG,
        ebpf::LD_2B_REG => ebpf::LD_H_REG,
        ebpf::LD_4B_REG => ebpf::LD_W_REG,
        ebpf::LD_8B_REG => ebpf::LD_DW_REG,
        ebpf::ST_1B_IMM => ebpf::ST_B_IMM,
        ebpf::ST_2B_IMM => ebpf::ST_H_IMM,
        ebpf::ST_4B_IMM => ebpf::ST_W_IMM,
        ebpf::ST_8B_IMM => ebpf::ST_DW_IMM,
        ebpf::ST_1B_REG => ebpf::ST_B_REG,
        ebpf::ST_2B_REG => ebpf::ST_H_REG,
        ebpf::ST_4B_REG => ebpf::ST_W_REG,
        ebpf::ST_8B_REG => ebpf::ST_DW_REG,
        opcode => opcode,
    };
    if let Some((_, canonical)) = CANONICAL_PQR_OPCODES
        .iter()
        .find(|(raw, _)| *raw == insn.opc)
    {
        insn.opc = *canonical;
    }
    if insn.opc == ebpf::CALL_REG {
        insn.imm = i64::from(insn.src);
    }
    insn
}

fn parse_pc(value: &str) -> Result<usize, Box<dyn Error>> {
    let parsed = if let Some(hex) = value.strip_prefix("0x") {
        usize::from_str_radix(hex, 16)?
    } else {
        value.parse()?
    };
    Ok(parsed)
}

#[derive(Default)]
struct LiftContext {
    remaining: u64,
}

const LOG_HELPER_ID: i64 = 1;
const LOG_FORMAT_SUMMARY_HELPER_ID: i64 = 15;
// sylana call-argument recorder; redirected calls become this external helper.
const RECORD_CALL_HELPER_ID: i64 = 16;

fn is_call(insn: &ebpf::Insn) -> bool {
    insn.opc == ebpf::CALL_IMM || insn.opc == ebpf::CALL_REG
}

fn is_control_flow(insn: &ebpf::Insn) -> bool {
    matches!(insn.opc & 0x07, ebpf::BPF_JMP64 | ebpf::BPF_JMP32)
}

fn writes_register(insn: &ebpf::Insn, register: u8) -> bool {
    if insn.dst != register {
        return false;
    }
    matches!(
        insn.opc & 0x07,
        ebpf::BPF_LD | ebpf::BPF_LDX | ebpf::BPF_ALU32_LOAD | ebpf::BPF_ALU64_STORE | ebpf::BPF_PQR
    )
}

fn stack_vec_output_before(insns: &[ebpf::Insn], call_pc: usize, output_offset: i16) -> bool {
    let mut saw_add = false;
    for insn in insns[..call_pc].iter().rev().take(12) {
        if is_call(insn) || is_control_flow(insn) {
            return false;
        }
        if !writes_register(insn, 1) {
            continue;
        }
        if !saw_add {
            if insn.opc != ebpf::ADD64_IMM || insn.imm != i64::from(output_offset) {
                return false;
            }
            saw_add = true;
        } else {
            return insn.opc == ebpf::MOV64_REG && insn.src == 10;
        }
    }
    false
}

// Match the Rust Vec<u8>-to-sol_log_ call shape; require a shared producer target to reject one-off calls.
fn find_log_format_calls(insns: &[ebpf::Insn]) -> Vec<usize> {
    let mut candidates = Vec::<(usize, usize)>::new();
    for call_pc in 0..insns.len().saturating_sub(3) {
        let call = &insns[call_pc];
        if call.opc != ebpf::CALL_IMM || call.src != 1 {
            continue;
        }
        let pointer_load = &insns[call_pc + 1];
        let length_load = &insns[call_pc + 2];
        let log_call = &insns[call_pc + 3];
        if pointer_load.opc != ebpf::LD_DW_REG
            || pointer_load.dst != 1
            || pointer_load.src != 10
            || length_load.opc != ebpf::LD_DW_REG
            || length_load.dst != 2
            || length_load.src != 10
            || i32::from(length_load.off) != i32::from(pointer_load.off) + 16
            || log_call.opc != ebpf::CALL_IMM
            || log_call.src != 0
            || log_call.imm != LOG_HELPER_ID
            || !stack_vec_output_before(insns, call_pc, pointer_load.off)
        {
            continue;
        }
        let target = i64::try_from(call_pc)
            .ok()
            .and_then(|pc| pc.checked_add(1 + call.imm))
            .and_then(|pc| usize::try_from(pc).ok());
        if let Some(target) = target.filter(|target| *target < insns.len()) {
            candidates.push((call_pc, target));
        }
    }

    let mut uses_by_target = BTreeMap::<usize, usize>::new();
    for (_, target) in &candidates {
        *uses_by_target.entry(*target).or_default() += 1;
    }
    candidates
        .into_iter()
        .filter_map(|(pc, target)| (uses_by_target[&target] >= 2).then_some(pc))
        .collect()
}

fn rust_decimal_digit_table() -> Vec<u8> {
    let mut table = Vec::with_capacity(200);
    for value in 0..100u8 {
        table.push(b'0' + value / 10);
        table.push(b'0' + value % 10);
    }
    table
}

fn readonly_region_ends(contents: &[u8], text_length: usize) -> (Vec<usize>, usize) {
    let mut ends = BTreeSet::from([contents.len()]);
    let digit_table = rust_decimal_digit_table();
    let mut search_start = 0;
    let mut hot_ranges = 0;
    while let Some(relative) = contents[search_start..]
        .windows(digit_table.len())
        .position(|window| window == digit_table)
    {
        let start = search_start + relative;
        if start != 0 {
            ends.insert(start);
        }
        ends.insert(start + digit_table.len());
        hot_ranges += 1;
        search_start = start + digit_table.len();
    }
    if hot_ranges == 0 && text_length != 0 {
        ends.insert(text_length);
    }
    (
        ends.into_iter().filter(|end| *end != 0).collect(),
        hot_ranges,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn insn(opc: u8, dst: u8, src: u8, off: i16, imm: i64) -> ebpf::Insn {
        ebpf::Insn {
            ptr: 0,
            opc,
            dst,
            src,
            off,
            imm,
        }
    }

    fn append_log_format_site(code: &mut Vec<ebpf::Insn>, target: usize, output: i16) -> usize {
        code.push(insn(ebpf::MOV64_REG, 1, 10, 0, 0));
        code.push(insn(ebpf::ADD64_IMM, 1, 0, 0, i64::from(output)));
        code.push(insn(ebpf::MOV64_REG, 2, 3, 0, 0));
        let call_pc = code.len();
        code.push(insn(
            ebpf::CALL_IMM,
            0,
            1,
            0,
            i64::try_from(target).unwrap() - i64::try_from(call_pc).unwrap() - 1,
        ));
        code.push(insn(ebpf::LD_DW_REG, 1, 10, output, 0));
        code.push(insn(ebpf::LD_DW_REG, 2, 10, output + 16, 0));
        code.push(insn(ebpf::CALL_IMM, 0, 0, 0, LOG_HELPER_ID));
        call_pc
    }

    #[test]
    fn recognizes_shared_stack_vec_producer_used_only_by_log_shape() {
        let target = 40;
        let mut code = Vec::new();
        let first = append_log_format_site(&mut code, target, -64);
        code.push(insn(ebpf::MOV64_REG, 0, 0, 0, 0));
        let second = append_log_format_site(&mut code, target, -96);
        code.resize_with(target + 1, || insn(ebpf::MOV64_REG, 0, 0, 0, 0));
        assert_eq!(find_log_format_calls(&code), vec![first, second]);
    }

    #[test]
    fn rejects_one_off_or_non_vec_log_producers() {
        let target = 40;
        let mut code = Vec::new();
        let _one_off = append_log_format_site(&mut code, target, -64);
        code.resize_with(target + 1, || insn(ebpf::MOV64_REG, 0, 0, 0, 0));
        assert!(find_log_format_calls(&code).is_empty());

        let mut code = Vec::new();
        let first = append_log_format_site(&mut code, target, -64);
        code[first + 2].off = -40; // length is not Vec's output + 16
        let _second = append_log_format_site(&mut code, target, -96);
        code.resize_with(target + 1, || insn(ebpf::MOV64_REG, 0, 0, 0, 0));
        assert!(find_log_format_calls(&code).is_empty());
    }

    #[test]
    fn isolates_compiler_decimal_table_without_artifact_offsets() {
        let mut contents = vec![0xaa; 32];
        contents.extend(rust_decimal_digit_table());
        contents.extend([0xbb; 16]);
        let (ends, hot_ranges) = readonly_region_ends(&contents, 24);
        assert_eq!(hot_ranges, 1);
        assert_eq!(ends, vec![32, 232, 248]);
    }

    #[test]
    fn canonicalizes_only_v2_memory_and_callx_encodings() {
        let load = insn(ebpf::LD_8B_REG, 3, 4, -8, 0);
        assert_eq!(
            canonicalize_encoding(load.clone(), SBPFVersion::V1).opc,
            ebpf::LD_8B_REG
        );
        assert_eq!(
            canonicalize_encoding(load, SBPFVersion::V2).opc,
            ebpf::LD_DW_REG
        );

        let callx = insn(ebpf::CALL_REG, 0, 7, 0, 0);
        assert_eq!(canonicalize_encoding(callx.clone(), SBPFVersion::V1).imm, 0);
        assert_eq!(canonicalize_encoding(callx, SBPFVersion::V2).imm, 7);

        let pqr = insn(ebpf::UHMUL64_REG, 2, 3, 0, 0);
        assert_eq!(canonicalize_encoding(pqr, SBPFVersion::V2).opc, 0x48);
    }

    #[test]
    fn accepts_64_byte_symbol_name_rejected_by_upstream_parser() {
        let mut bytes = vec![b'x'; 64];
        bytes.push(0);
        let section = Elf64Shdr {
            sh_name: 0,
            sh_type: 0,
            sh_flags: 0,
            sh_addr: 0,
            sh_offset: 0,
            sh_size: bytes.len() as u64,
            sh_link: 0,
            sh_info: 0,
            sh_addralign: 1,
            sh_entsize: 0,
        };
        assert_eq!(
            bounded_string_in_section(&bytes, &section, 0),
            Some(&bytes[..64])
        );
    }
}

impl ContextObject for LiftContext {
    fn consume(&mut self, amount: u64) {
        self.remaining = self.remaining.saturating_sub(amount);
    }

    fn get_remaining(&self) -> u64 {
        self.remaining
    }

    fn active_mapping_ptr(&mut self) -> NonNull<MemoryMapping> {
        unreachable!("the normalization tool never executes a syscall")
    }
}

declare_builtin_function!(
    DummySyscall,
    fn rust(
        _vm: &mut LiftContext,
        _arg_a: u64,
        _arg_b: u64,
        _arg_c: u64,
        _arg_d: u64,
        _arg_e: u64,
    ) -> Result<u64, std::io::Error> {
        Ok(0)
    }
);

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args_os().skip(1);
    let input = PathBuf::from(args.next().ok_or_else(usage)?);
    let output = PathBuf::from(args.next().ok_or_else(usage)?);
    let mut function_pc = None;
    let mut summarize_log_formats = false;
    let mut record_calls_to = None;
    while let Some(flag) = args.next() {
        if flag == "--function-pc" && function_pc.is_none() {
            let value = args.next().ok_or_else(usage)?;
            function_pc = Some(parse_pc(&value.to_string_lossy())?);
        } else if flag == "--summarize-log-formats" && !summarize_log_formats {
            summarize_log_formats = true;
        } else if flag == "--record-calls-to" && record_calls_to.is_none() {
            let value = args.next().ok_or_else(usage)?;
            record_calls_to = Some(parse_pc(&value.to_string_lossy())?);
        } else {
            return Err(usage().into());
        }
    }

    // Registering every helper lets solana-sbpf do authoritative ELF relocation before normalization.
    let helper_names = [
        "sol_log_",
        "abort",
        "sol_memset_",
        "sol_memcpy_",
        "sol_invoke_signed_rust",
        "sol_memcmp_",
        "sol_try_find_program_address",
        "sol_sha256",
        "sol_log_data",
        "sol_log_pubkey",
        "sol_create_program_address",
        "sol_get_clock_sysvar",
        "sol_get_rent_sysvar",
        "sol_memmove_",
        "sbpf_log_format_summary",
        "sylana_record_call_args",
        "sol_set_return_data",
        "sol_get_return_data",
    ];
    let mut loader = BuiltinProgram::new_loader(Config {
        // Labels are recovered below; relocation and VM validation stay authoritative.
        enable_symbol_and_section_labels: false,
        ..Config::default()
    });
    for name in helper_names {
        DummySyscall::register(&mut loader, name)?;
    }

    let elf = fs::read(&input)?;
    println!("AA");
    let function_labels = elf_function_labels(&elf)?;
    let executable = Executable::<LiftContext>::from_elf(&elf, Arc::new(loader))?;
    let version = executable.get_sbpf_version();
    let version_number = version_number(version).ok_or_else(|| {
        format!("this llvmbpf adapter supports sBPF v0-v2; input uses {version:?}")
    })?;

    let entry_pc = executable.get_entrypoint_instruction_offset();
    let (text_vm_addr, relocated_text) = executable.get_text_bytes();
    let ro_region = executable.get_ro_region();
    let relocated_ro_section = executable.get_ro_section();
    let mut local_functions = BTreeMap::new();
    for (key, (name, pc)) in executable.get_function_registry().iter() {
        let name = function_labels
            .get(&pc)
            .cloned()
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| {
                if name.is_empty() {
                    format!("function_{pc}")
                } else {
                    String::from_utf8_lossy(name).into_owned()
                }
            });
        local_functions.insert(key, (name, pc));
    }
    for (pc, name) in function_labels {
        let key = if name == "entrypoint" {
            ebpf::hash_symbol_name(name.as_bytes())
        } else {
            ebpf::hash_symbol_name(&pc.to_le_bytes())
        };
        match local_functions.get(&key) {
            Some((_existing_name, existing_pc)) if *existing_pc != pc => {}
            Some(_) => {}
            None => {
                local_functions.insert(key, (name, pc));
            }
        }
    }

    let helper_ids: BTreeMap<u32, (i32, &str)> = helper_names
        .iter()
        .enumerate()
        .map(|(index, name)| {
            (
                ebpf::hash_symbol_name(name.as_bytes()),
                ((index + 1) as i32, *name),
            )
        })
        .collect();

    // Function mode prefixes a trampoline: load r0..r9 from a register context, call the target, then exit.
    let mut prefix = Vec::<ebpf::Insn>::new();
    if let Some(target_pc) = function_pc {
        if !local_functions.values().any(|(_name, pc)| *pc == target_pc) {
            return Err(format!("pc {target_pc} is not a registered local function entry").into());
        }
        prefix.push(ebpf::Insn {
            ptr: 0,
            opc: ebpf::MOV64_REG,
            dst: 9,
            src: 1,
            off: 0,
            imm: 0,
        });
        for register in 0..REGISTER_COUNT {
            prefix.push(ebpf::Insn {
                ptr: 0,
                opc: ebpf::LD_DW_REG,
                dst: register,
                src: 9,
                off: i16::from(register) * 8,
                imm: 0,
            });
        }
        let call_pc = prefix.len();
        let original_shift = call_pc + 2; // the call itself and the final exit
        let shifted_target = original_shift + target_pc;
        prefix.push(ebpf::Insn {
            ptr: 0,
            opc: ebpf::CALL_IMM,
            dst: 0,
            src: 1,
            off: 0,
            imm: i64::try_from(shifted_target)? - i64::try_from(call_pc)? - 1,
        });
        prefix.push(ebpf::Insn {
            ptr: 0,
            opc: ebpf::EXIT,
            dst: 0,
            src: 0,
            off: 0,
            imm: 0,
        });
    }

    let prefix_instructions = prefix.len();
    let normalized_entry_pc = if function_pc.is_some() { 0 } else { entry_pc };
    let mut normalized = Vec::<ebpf::Insn>::with_capacity(
        relocated_text.len() / ebpf::INSN_SIZE + prefix_instructions,
    );
    normalized.extend(prefix);

    let instruction_count = relocated_text.len() / ebpf::INSN_SIZE;
    let mut rewritten_local_calls = 0usize;
    let mut rewritten_syscalls = BTreeMap::<String, usize>::new();
    let mut callx_by_register = BTreeMap::<u8, usize>::new();
    for pc in 0..instruction_count {
        let mut insn = canonicalize_encoding(ebpf::get_insn(relocated_text, pc), version);
        if insn.opc == ebpf::CALL_IMM {
            let key = insn.imm as u32;
            if let Some((_name, target_pc)) = local_functions.get(&key) {
                if record_calls_to == Some(*target_pc) {
                    // Redirect calls to the recorded function into the arg recorder.
                    insn.src = 0;
                    insn.imm = RECORD_CALL_HELPER_ID;
                    *rewritten_syscalls
                        .entry("sylana_record_call_args".to_string())
                        .or_default() += 1;
                } else {
                    insn.src = 1;
                    insn.imm = i64::try_from(*target_pc)? - i64::try_from(pc)? - 1;
                    rewritten_local_calls += 1;
                }
            } else if let Some((helper_id, helper_name)) = helper_ids.get(&key) {
                // llvmbpf treats src=0 calls as external helpers indexed by imm.
                insn.src = 0;
                insn.imm = i64::from(*helper_id);
                *rewritten_syscalls
                    .entry((*helper_name).to_string())
                    .or_default() += 1;
            } else if insn.src != 1 {
                return Err(format!("unresolved call key {key:#x} at pc {pc}").into());
            }
        } else if insn.opc == ebpf::CALL_REG {
            let register = u8::try_from(insn.imm)?;
            if register > 10 {
                return Err(format!("invalid callx register r{register} at pc {pc}").into());
            }
            // Keep CALL_REG intact; the LLVM emitter lowers it through the target table below.
            *callx_by_register.entry(register).or_default() += 1;
        }
        normalized.push(insn);
    }

    let summarized_log_formats = if summarize_log_formats {
        let call_pcs = find_log_format_calls(&normalized);
        for pc in &call_pcs {
            let insn = &mut normalized[*pc];
            insn.src = 0;
            insn.imm = LOG_FORMAT_SUMMARY_HELPER_ID;
        }
        call_pcs
    } else {
        Vec::new()
    };

    let normalized_bytes: Vec<u8> = normalized.iter().flat_map(|insn| insn.to_array()).collect();
    fs::write(&output, &normalized_bytes)?;
    let mut version_output = output.as_os_str().to_os_string();
    version_output.push(".sbpf-version");
    let version_path = PathBuf::from(&version_output);
    fs::write(&version_path, format!("{version_number}\n"))?;
    let mut entry_output = output.as_os_str().to_os_string();
    entry_output.push(".entry-pc");
    let entry_path = PathBuf::from(&entry_output);
    fs::write(&entry_path, format!("{normalized_entry_pc}\n"))?;
    let mut rodata_output = output.as_os_str().to_os_string();
    rodata_output.push(".rodata");
    fs::write(PathBuf::from(&rodata_output), relocated_ro_section)?;
    let (rodata_region_ends, rodata_hot_ranges) =
        readonly_region_ends(relocated_ro_section, relocated_text.len());
    let mut rodata_regions_output = output.as_os_str().to_os_string();
    rodata_regions_output.push(".rodata-regions.h");
    let rodata_regions_path = PathBuf::from(&rodata_regions_output);
    let mut rodata_regions_header = String::from(
        "#ifndef SBPF_RELOCATED_RODATA_REGIONS_H\n#define SBPF_RELOCATED_RODATA_REGIONS_H\n#include <stdint.h>\nstatic const uint64_t sbpf_relocated_rodata_region_ends[] = {\n",
    );
    for end in &rodata_region_ends {
        rodata_regions_header.push_str(&format!("  UINT64_C({end}),\n"));
    }
    rodata_regions_header.push_str("};\n");
    rodata_regions_header.push_str("#define SBPF_RELOCATED_RODATA_REGION_COUNT \\\n");
    rodata_regions_header.push_str("  (sizeof(sbpf_relocated_rodata_region_ends) / \\\n");
    rodata_regions_header.push_str("   sizeof(sbpf_relocated_rodata_region_ends[0]))\n#endif\n");
    fs::write(&rodata_regions_path, rodata_regions_header)?;

    // Collect code pointers from LDDW or relocated ro data as CALL_REG targets; covers Rust vtables and thunks.
    let text_vm_end = text_vm_addr
        .checked_add(u64::try_from(relocated_text.len())?)
        .ok_or("text VM address overflow")?;
    let mut callx_targets = BTreeSet::<u64>::new();
    let mut add_code_pointer = |address: u64| {
        if address >= text_vm_addr
            && address < text_vm_end
            && (address - text_vm_addr) % ebpf::INSN_SIZE as u64 == 0
        {
            callx_targets.insert(address);
        }
    };
    for pc in 0..instruction_count.saturating_sub(1) {
        let mut insn = ebpf::get_insn(relocated_text, pc);
        if insn.opc == ebpf::LD_DW_IMM {
            ebpf::augment_lddw_unchecked(relocated_text, &mut insn);
            add_code_pointer(insn.imm as u64);
        } else if version == SBPFVersion::V2
            && (insn.opc == ebpf::MOV32_IMM || insn.opc == ebpf::MOV64_IMM)
        {
            let high = ebpf::get_insn(relocated_text, pc + 1);
            if high.opc == ebpf::HOR64_IMM && high.dst == insn.dst {
                add_code_pointer((insn.imm as u64) | (high.imm as u64).wrapping_shl(32));
            }
        }
    }
    for bytes in relocated_ro_section.chunks_exact(8) {
        add_code_pointer(u64::from_le_bytes(bytes.try_into()?));
    }
    let mut callx_targets_output = output.as_os_str().to_os_string();
    callx_targets_output.push(".callx-targets");
    let callx_targets_path = PathBuf::from(&callx_targets_output);
    let mut callx_targets_text = String::new();
    for address in &callx_targets {
        let original_pc = usize::try_from((address - text_vm_addr) / ebpf::INSN_SIZE as u64)?;
        let normalized_pc = original_pc + prefix_instructions;
        callx_targets_text.push_str(&format!("{address:#x} {normalized_pc}\n"));
    }
    fs::write(&callx_targets_path, callx_targets_text)?;
    println!("input={}", input.display());
    println!("output={}", output.display());
    println!("sbpf_version_output={}", version_path.display());
    println!("entry_pc_output={}", entry_path.display());
    println!("rodata_output={}", PathBuf::from(&rodata_output).display());
    println!("rodata_vm_addr={:#x}", ro_region.vm_addr);
    println!("rodata_len={}", ro_region.len);
    println!("rodata_regions_output={}", rodata_regions_path.display());
    println!("rodata_regions.count={}", rodata_region_ends.len());
    println!("rodata_hot_ranges.count={rodata_hot_ranges}");
    for end in &rodata_region_ends {
        println!("rodata_region.end={end}");
    }
    println!("text_vm_addr={text_vm_addr:#x}");
    println!("sbpf_version={version:?}");
    println!("entry_pc={entry_pc}");
    println!("normalized_entry_pc={normalized_entry_pc}");
    println!(
        "mode={}",
        function_pc
            .map(|pc| format!("function:{pc}"))
            .unwrap_or_else(|| "program".to_string())
    );
    println!("original_pc_shift={prefix_instructions}");
    println!("input_instructions={instruction_count}");
    println!("output_instructions={}", normalized.len());
    println!("functions.count={}", local_functions.len());
    for (key, (name, pc)) in &local_functions {
        println!("function.{pc}={key:#010x},{name}");
    }
    println!("rewritten_local_calls={rewritten_local_calls}");
    for (name, count) in rewritten_syscalls {
        println!("rewritten_syscall.{name}={count}");
    }
    println!(
        "summarize_log_formats={}",
        if summarize_log_formats {
            "enabled"
        } else {
            "disabled"
        }
    );
    println!(
        "summarized_log_formats.count={}",
        summarized_log_formats.len()
    );
    for pc in summarized_log_formats {
        println!("summarized_log_format.pc={pc}");
    }
    println!("callx_targets_output={}", callx_targets_path.display());
    println!("callx_targets.count={}", callx_targets.len());
    for (register, count) in callx_by_register {
        println!("callx.r{register}={count}");
    }
    for (index, name) in helper_names.iter().enumerate() {
        println!("helper.{}={name}", index + 1);
    }
    Ok(())
}
