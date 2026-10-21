#include "llvmbpf.hpp"

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

int main(int argc, char **argv) {
    if (argc != 3) {
        std::cerr << "usage: sbpf-llvm-emit NORMALIZED.bin CALLX-TARGETS\n";
        return 2;
    }

    std::ifstream input(argv[1], std::ios::binary);
    if (!input) {
        std::cerr << "failed to open " << argv[1] << "\n";
        return 2;
    }
    std::vector<std::uint8_t> code{
        std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};

    const std::string version_path = std::string(argv[1]) + ".sbpf-version";
    std::ifstream version_input(version_path);
    unsigned int sbpf_version;
    if (!(version_input >> sbpf_version) || sbpf_version > 2) {
        std::cerr << "invalid or missing sBPF version file " << version_path
                  << "\n";
        return 2;
    }
    const std::string entry_path = std::string(argv[1]) + ".entry-pc";
    std::ifstream entry_input(entry_path);
    std::uint64_t entry_pc;
    if (!(entry_input >> entry_pc) || entry_pc > UINT32_MAX) {
        std::cerr << "invalid or missing sBPF entry PC file " << entry_path
                  << "\n";
        return 2;
    }

    bpftime::llvmbpf_vm vm;
    if (vm.set_sbpf_version(sbpf_version) != 0) {
        std::cerr << vm.get_error_message() << "\n";
        return 1;
    }
    if (vm.load_code(code.data(), code.size()) != 0) {
        std::cerr << vm.get_error_message() << "\n";
        return 1;
    }
    if (vm.set_entry_pc(static_cast<std::uint32_t>(entry_pc)) != 0) {
        std::cerr << vm.get_error_message() << "\n";
        return 1;
    }

    std::ifstream target_input(argv[2]);
    if (!target_input) {
        std::cerr << "failed to open " << argv[2] << "\n";
        return 2;
    }
    std::vector<bpftime::sbpf_callx_target> callx_targets;
    std::string guest_address_text;
    std::uint64_t instruction_pc;
    while (target_input >> guest_address_text >> instruction_pc) {
        char *end = nullptr;
        errno = 0;
        const auto guest_address =
            std::strtoull(guest_address_text.c_str(), &end, 0);
        if (errno != 0 || end == guest_address_text.c_str() || *end != '\0' ||
            instruction_pc > UINT32_MAX) {
            std::cerr << "invalid callx target row: " << guest_address_text
                      << " " << instruction_pc << "\n";
            return 2;
        }
        callx_targets.push_back(
            {guest_address, static_cast<std::uint32_t>(instruction_pc)});
    }
    if (!target_input.eof()) {
        std::cerr << "invalid callx target file " << argv[2] << "\n";
        return 2;
    }
    if (vm.set_sbpf_callx_targets(callx_targets) != 0) {
        std::cerr << vm.get_error_message() << "\n";
        return 1;
    }

    // IDs must match sbpf-normalize's output metadata.
    const char *helpers[] = {
        "unused", "sol_log_", "abort", "sol_memset_", "sol_memcpy_",
        "sol_invoke_signed_rust", "sol_memcmp_", "sol_try_find_program_address",
        "sol_sha256", "sol_log_data", "sol_log_pubkey",
        "sol_create_program_address", "sol_get_clock_sysvar",
        "sol_get_rent_sysvar", "sol_memmove_",
        "sbpf_log_format_summary", "sylana_record_call_args",
        "sol_set_return_data", "sol_get_return_data"};
    for (std::size_t id = 1; id < std::size(helpers); ++id) {
        if (vm.register_external_function(id, helpers[id], nullptr) != 0) {
            std::cerr << vm.get_error_message() << "\n";
            return 1;
        }
    }
    // Emit unoptimized; opt is a separate pass to keep instruction-to-block mapping.
    vm.set_optimization_level(0);
    if (!vm.do_aot_compile(true)) {
        std::cerr << vm.get_error_message() << "\n";
        return 1;
    }
    return 0;
}
