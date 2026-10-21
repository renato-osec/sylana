#include <assert.h>
#include <stdint.h>
#include <string.h>

#include <klee/klee.h>

#include "asset_model.h"
#include "process_instruction_call.h"

extern uint64_t bpf_main(void *register_context, uint64_t context_size);

int main(void) {
  uint64_t registers[10] = {0};
  uint64_t result[3] = {0};
#ifdef PROCESS_INSTRUCTION_SELECTOR
  struct process_instruction_call_frame dispatcher_frame;
  uint8_t instruction_selector = PROCESS_INSTRUCTION_SELECTOR;
#endif
  struct pubkey program_id = {{UINT64_C(0x42), 0, 0, 0}};
  struct pubkey record_owner = {{0}};
  struct pubkey recipient_owner = {{UINT64_C(0x99), 0, 0, 0}};
  struct pubkey keys[3] = {{{1, 0, 0, 0}}, {{2, 0, 0, 0}}, {{3, 0, 0, 0}}};
  uint64_t requested_amount = 0;
  uint8_t record_data[8] = {0};
  uint64_t treasury_balance = 100;
  uint64_t recipient_balance = 10;

  struct rc_refcell_slice record_data_rc = {1, 1, 0, record_data,
                                            sizeof(record_data)};
  struct rc_refcell_u64 treasury_lamports_rc = {1, 1, 0, &treasury_balance};
  struct rc_refcell_u64 recipient_lamports_rc = {1, 1, 0, &recipient_balance};
  struct account_info accounts[3] = {0};

  klee_make_symbolic(&record_owner, sizeof(record_owner), "record.owner");
  klee_make_symbolic(&requested_amount, sizeof(requested_amount),
                     "record.data.amount");
#ifdef PROCESS_INSTRUCTION_SYMBOLIC_SELECTOR
  klee_make_symbolic(&instruction_selector, sizeof(instruction_selector),
                     "instruction.selector");
#endif
  // Focus this probe on an attacker-controlled, non-program-owned record.
  klee_assume(record_owner.words[0] != program_id.words[0]);
  memcpy(record_data, &requested_amount, sizeof(requested_amount));

  accounts[0].key = &keys[0];
  accounts[0].data = &record_data_rc;
  accounts[0].owner = &record_owner;
  accounts[1].key = &keys[1];
  accounts[1].lamports = &treasury_lamports_rc;
  accounts[1].owner = &program_id;
  accounts[1].is_writable = 1;
  accounts[2].key = &keys[2];
  accounts[2].lamports = &recipient_lamports_rc;
  accounts[2].owner = &recipient_owner;
  accounts[2].is_writable = 1;

  const struct asset_balance_view treasury_view = {&accounts[1],
                                                   ASSET_BALANCE_LAMPORTS};
  const struct asset_balance_view recipient_view = {&accounts[2],
                                                    ASSET_BALANCE_LAMPORTS};
  const uint64_t treasury_before = asset_balance_read(treasury_view);
  const uint64_t recipient_before = asset_balance_read(recipient_view);

  registers[1] = (uint64_t)(uintptr_t)result;
  registers[2] = (uint64_t)(uintptr_t)&program_id;
  registers[3] = (uint64_t)(uintptr_t)accounts;
  registers[4] = 3;
#ifdef PROCESS_INSTRUCTION_SELECTOR
  prepare_process_instruction_call(registers, &dispatcher_frame,
                                   &instruction_selector, 1);
#endif

  (void)bpf_main(registers, sizeof(registers));

  const int transferred =
      lifted_program_succeeded(result) &&
      asset_transfer_observed(
          treasury_before, asset_balance_read(treasury_view), recipient_before,
          asset_balance_read(recipient_view));
  if (transferred) {
    klee_assert(!pubkeys_equal(&record_owner, &program_id));
    klee_report_error(__FILE__, __LINE__,
                      "treasury transfer from an unowned record",
                      "unauthorized-transfer.err");
  }
  return 0;
}
