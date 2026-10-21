// Handler-mode harness for instruction 4 (system_transfer_vulnerable): calls
// process_instruction directly (function-mode lift) with C-built AccountInfos,
// so it bypasses the entrypoint deserialize. It proves the System-program CPI
// model actually moves lamports payer -> recipient for a symbolic amount.
#include <stdint.h>
#include <string.h>

#include <klee/klee.h>

#include "asset_model.h"
#include "process_instruction_call.h"

extern uint64_t bpf_main(void *register_context, uint64_t context_size);

int main(void) {
  uint64_t registers[10] = {0};
  uint64_t result[3] = {0};
  struct process_instruction_call_frame dispatcher_frame;
  uint8_t instruction_selector = 4;

  struct pubkey program_id = {{UINT64_C(0x42), 0, 0, 0}};
  struct pubkey system_key = {{0, 0, 0, 0}};  // System program id
  struct pubkey record_key = {{1, 0, 0, 0}};
  struct pubkey payer_key = {{2, 0, 0, 0}};
  struct pubkey recipient_key = {{3, 0, 0, 0}};
  struct pubkey record_owner = {{UINT64_C(0x55), 0, 0, 0}};

  uint64_t requested_amount = 0;
  uint8_t record_data[8] = {0};
  uint8_t empty_data[1] = {0};
  uint64_t payer_balance = 100;
  uint64_t recipient_balance = 10;
  uint64_t system_balance = 1;

  // invoke() clones the payer/recipient/system AccountInfos, and cloning an Rc
  // dereferences its box, so every account passed to the CPI needs non-null
  // lamports and data RefCells.
  struct rc_refcell_slice record_data_rc = {1, 1, 0, record_data, sizeof(record_data)};
  struct rc_refcell_slice payer_data_rc = {1, 1, 0, empty_data, 0};
  struct rc_refcell_slice recipient_data_rc = {1, 1, 0, empty_data, 0};
  struct rc_refcell_slice system_data_rc = {1, 1, 0, empty_data, 0};
  struct rc_refcell_u64 payer_lamports_rc = {1, 1, 0, &payer_balance};
  struct rc_refcell_u64 recipient_lamports_rc = {1, 1, 0, &recipient_balance};
  struct rc_refcell_u64 system_lamports_rc = {1, 1, 0, &system_balance};
  struct account_info accounts[4] = {0};

  klee_make_symbolic(&requested_amount, sizeof(requested_amount), "record.amount");
  memcpy(record_data, &requested_amount, sizeof(requested_amount));

  accounts[0].key = &record_key;
  accounts[0].lamports = &payer_lamports_rc;
  accounts[0].data = &record_data_rc;
  accounts[0].owner = &record_owner;
  accounts[1].key = &payer_key;
  accounts[1].lamports = &payer_lamports_rc;
  accounts[1].data = &payer_data_rc;
  accounts[1].owner = &system_key;   // wallet owned by the System program
  accounts[1].is_signer = 1;
  accounts[1].is_writable = 1;
  accounts[2].key = &recipient_key;
  accounts[2].lamports = &recipient_lamports_rc;
  accounts[2].data = &recipient_data_rc;
  accounts[2].owner = &system_key;
  accounts[2].is_writable = 1;
  accounts[3].key = &system_key;     // the System program account itself
  accounts[3].lamports = &system_lamports_rc;
  accounts[3].data = &system_data_rc;
  accounts[3].owner = &record_owner;
  accounts[3].executable = 1;

  const struct asset_balance_view payer_view = {&accounts[1], ASSET_BALANCE_LAMPORTS};
  const struct asset_balance_view recipient_view = {&accounts[2], ASSET_BALANCE_LAMPORTS};
  const uint64_t payer_before = asset_balance_read(payer_view);
  const uint64_t recipient_before = asset_balance_read(recipient_view);

  sbpf_runtime_initialize();
  registers[1] = (uint64_t)(uintptr_t)result;
  registers[2] = (uint64_t)(uintptr_t)&program_id;
  registers[3] = (uint64_t)(uintptr_t)accounts;
  registers[4] = 4;
  prepare_process_instruction_call(registers, &dispatcher_frame, &instruction_selector, 1);

  (void)bpf_main(registers, sizeof(registers));

  const int transferred =
      lifted_program_succeeded(result) &&
      asset_transfer_observed(payer_before, asset_balance_read(payer_view),
                              recipient_before, asset_balance_read(recipient_view));
  if (transferred) {
    // The System CPI moved lamports for a symbolic amount.
    klee_report_error(__FILE__, __LINE__, "system transfer committed",
                      "system-transfer.err");
  }
  return 0;
}
