// Handler-mode harness for instruction 5 (check_clock): reads the Clock and
// Rent sysvars via the syscalls and transfers 1 lamport only if they look sane.
// The canonical sysvar values (slot=100, rent>0) make the read succeed and the
// transfer commit, proving sysvar reads simulate end-to-end.
#include <stdint.h>

#include <klee/klee.h>

#include "asset_model.h"
#include "process_instruction_call.h"

extern uint64_t bpf_main(void *register_context, uint64_t context_size);

int main(void) {
  uint64_t registers[10] = {0};
  uint64_t result[3] = {0};
  struct process_instruction_call_frame dispatcher_frame;
  uint8_t instruction_selector = 5;

  struct pubkey program_id = {{UINT64_C(0x42), 0, 0, 0}};
  struct pubkey treasury_key = {{1, 0, 0, 0}};
  struct pubkey recipient_key = {{2, 0, 0, 0}};
  uint64_t treasury_balance = 100;
  uint64_t recipient_balance = 10;

  struct rc_refcell_u64 treasury_lamports_rc = {1, 1, 0, &treasury_balance};
  struct rc_refcell_u64 recipient_lamports_rc = {1, 1, 0, &recipient_balance};
  struct account_info accounts[2] = {0};

  accounts[0].key = &treasury_key;
  accounts[0].lamports = &treasury_lamports_rc;
  accounts[0].owner = &program_id;
  accounts[0].is_writable = 1;
  accounts[1].key = &recipient_key;
  accounts[1].lamports = &recipient_lamports_rc;
  accounts[1].owner = &program_id;
  accounts[1].is_writable = 1;

  const struct asset_balance_view treasury_view = {&accounts[0], ASSET_BALANCE_LAMPORTS};
  const struct asset_balance_view recipient_view = {&accounts[1], ASSET_BALANCE_LAMPORTS};
  const uint64_t treasury_before = asset_balance_read(treasury_view);
  const uint64_t recipient_before = asset_balance_read(recipient_view);

  sbpf_runtime_initialize();
  registers[1] = (uint64_t)(uintptr_t)result;
  registers[2] = (uint64_t)(uintptr_t)&program_id;
  registers[3] = (uint64_t)(uintptr_t)accounts;
  registers[4] = 2;
  prepare_process_instruction_call(registers, &dispatcher_frame, &instruction_selector, 1);

  (void)bpf_main(registers, sizeof(registers));

  const int transferred =
      asset_transfer_observed(treasury_before, asset_balance_read(treasury_view),
                              recipient_before, asset_balance_read(recipient_view));
  // The lamport move is an observable side effect that commits before the
  // function returns, so it proves the sysvar gate (clock.slot>=1, rent>0) held
  // independent of the ProgramResult sret return.
  if (transferred) {
    klee_report_error(__FILE__, __LINE__, "sysvar-gated transfer committed",
                      "sysvar-transfer.err");
  } else {
    klee_report_error(__FILE__, __LINE__, "gate did not transfer",
                      "no-transfer.err");
  }
  return 0;
}
