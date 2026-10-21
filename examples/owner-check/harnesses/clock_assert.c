// Handler-mode harness for instruction 6 (assert_clock): reads Clock and Rent
// and returns Ok only if the canonical modeled values arrive. Ok proves the
// sysvar syscalls are read end-to-end and carry the right values.
#include <stdint.h>

#include <klee/klee.h>

#include "asset_model.h"
#include "process_instruction_call.h"

extern uint64_t bpf_main(void *register_context, uint64_t context_size);

int main(void) {
  uint64_t registers[10] = {0};
  uint64_t result[3] = {0};
  struct process_instruction_call_frame dispatcher_frame;
  uint8_t instruction_selector = 6;
  struct pubkey program_id = {{UINT64_C(0x42), 0, 0, 0}};
  struct account_info accounts[1] = {0};

  sbpf_runtime_initialize();
  registers[1] = (uint64_t)(uintptr_t)result;
  registers[2] = (uint64_t)(uintptr_t)&program_id;
  registers[3] = (uint64_t)(uintptr_t)accounts;
  registers[4] = 0;
  prepare_process_instruction_call(registers, &dispatcher_frame, &instruction_selector, 1);

  (void)bpf_main(registers, sizeof(registers));

  if (lifted_program_succeeded(result)) {
    klee_report_error(__FILE__, __LINE__, "sysvar canonical values read",
                      "sysvar-ok.err");
  } else {
    klee_report_error(__FILE__, __LINE__, "sysvar read wrong or errored",
                      "sysvar-bad.err");
  }
  return 0;
}
