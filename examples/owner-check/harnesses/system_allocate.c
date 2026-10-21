// Handler-mode harness for instruction 7 (system_allocate): allocates 100 bytes
// on a system-owned account via a System-program CPI, then asserts the account's
// data length reflects it. Proves the Allocate model updates the len (matching
// Agave's set_data_length) rather than no-opping.
#include <assert.h>
#include <stdint.h>

#include <klee/klee.h>

#include "asset_model.h"
#include "process_instruction_call.h"

extern uint64_t bpf_main(void *register_context, uint64_t context_size);

int main(void) {
  uint64_t registers[10] = {0};
  uint64_t result[3] = {0};
  struct process_instruction_call_frame dispatcher_frame;
  uint8_t instruction_selector = 7;

  struct pubkey program_id = {{UINT64_C(0x42), 0, 0, 0}};
  struct pubkey system_key = {{0, 0, 0, 0}};  // System program id
  struct pubkey target_key = {{1, 0, 0, 0}};

  uint8_t target_data[256] = {0};  // empty (len 0) with zeroed headroom
  uint8_t system_bytes[1] = {0};
  uint64_t target_balance = 1;
  uint64_t system_balance = 1;

  // invoke() clones the AccountInfos, and cloning an Rc dereferences its box,
  // so every account passed to the CPI needs non-null lamports and data cells.
  struct rc_refcell_slice target_data_rc = {1, 1, 0, target_data, 0};
  struct rc_refcell_slice system_data_rc = {1, 1, 0, system_bytes, 0};
  struct rc_refcell_u64 target_lamports_rc = {1, 1, 0, &target_balance};
  struct rc_refcell_u64 system_lamports_rc = {1, 1, 0, &system_balance};
  struct account_info accounts[2] = {0};

  accounts[0].key = &target_key;
  accounts[0].lamports = &target_lamports_rc;
  accounts[0].data = &target_data_rc;
  accounts[0].owner = &system_key;  // system-owned + empty -> allocatable
  accounts[0].is_signer = 1;
  accounts[0].is_writable = 1;
  accounts[1].key = &system_key;    // the System program account itself
  accounts[1].lamports = &system_lamports_rc;
  accounts[1].data = &system_data_rc;
  accounts[1].owner = &program_id;
  accounts[1].executable = 1;

  sbpf_runtime_initialize();
  registers[1] = (uint64_t)(uintptr_t)result;
  registers[2] = (uint64_t)(uintptr_t)&program_id;
  registers[3] = (uint64_t)(uintptr_t)accounts;
  registers[4] = 2;
  prepare_process_instruction_call(registers, &dispatcher_frame, &instruction_selector, 1);

  (void)bpf_main(registers, sizeof(registers));

  // The handler returns Ok only when data_len() == 100. Assert both the return
  // and the shared length, so a no-op Allocate would fail loudly.
  klee_assert(lifted_program_succeeded(result));
  klee_assert(target_data_rc.length == 100);
  klee_report_error(__FILE__, __LINE__, "allocate updated data length",
                    "allocate-ok.err");
  return 0;
}
