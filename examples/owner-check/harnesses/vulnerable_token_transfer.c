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
  struct pubkey mint = {{UINT64_C(0x77), 0, 0, 0}};
  struct pubkey source_authority = {{UINT64_C(0x88), 0, 0, 0}};
  struct pubkey destination_authority = {{UINT64_C(0x99), 0, 0, 0}};
  struct pubkey keys[5] = {{{1, 0, 0, 0}},
                           {{2, 0, 0, 0}},
                           {{3, 0, 0, 0}},
                           {{UINT64_C(0x88), 0, 0, 0}},
                           {{0}}};
  uint64_t requested_amount = 0;
  uint64_t source_initial_amount = 100;
  uint64_t destination_initial_amount = 10;
  uint8_t record_data[8] = {0};
  uint8_t source_data[TOKEN_ACCOUNT_BASE_LENGTH];
  uint8_t destination_data[TOKEN_ACCOUNT_BASE_LENGTH];
  uint8_t empty_data = 0;
  uint64_t lamports[5] = {1, 1, 1, 1, 1};
  struct rc_refcell_u64 lamports_rc[5];
  struct rc_refcell_slice data_rc[5];
  struct account_info accounts[5] = {0};

  keys[4] = SPL_TOKEN_PROGRAM_ID;
#ifdef SYMBOLIC_TOKEN_BALANCES
  klee_make_symbolic(&source_initial_amount, sizeof(source_initial_amount),
                     "source.amount");
  klee_make_symbolic(&destination_initial_amount,
                     sizeof(destination_initial_amount), "destination.amount");
#endif
  initialize_token_account_data(source_data, &mint, &source_authority,
                                source_initial_amount);
  initialize_token_account_data(destination_data, &mint, &destination_authority,
                                destination_initial_amount);

  for (unsigned index = 0; index < 5; ++index) {
    lamports_rc[index] = (struct rc_refcell_u64){1, 1, 0, &lamports[index]};
    data_rc[index] = (struct rc_refcell_slice){1, 1, 0, &empty_data, 0};
    accounts[index].key = &keys[index];
    accounts[index].lamports = &lamports_rc[index];
    accounts[index].data = &data_rc[index];
  }

  data_rc[0] =
      (struct rc_refcell_slice){1, 1, 0, record_data, sizeof(record_data)};
  data_rc[1] =
      (struct rc_refcell_slice){1, 1, 0, source_data, sizeof(source_data)};
  data_rc[2] = (struct rc_refcell_slice){1, 1, 0, destination_data,
                                         sizeof(destination_data)};

  accounts[0].owner = &record_owner;
  accounts[1].owner = &keys[4];
  accounts[1].is_writable = 1;
  accounts[2].owner = &keys[4];
  accounts[2].is_writable = 1;
  accounts[3].owner = &source_authority;
  accounts[3].is_signer = 1;
  accounts[4].executable = 1;

  const struct token_account_oracle_entry oracle[] = {
      {&accounts[1],
       &mint,
       &source_authority,
       TOKEN_PROGRAM_SPL,
       6,
       0,
       TOKEN_ORACLE_PLAIN_TRANSFER,
       {0}},
      {&accounts[2],
       &mint,
       &destination_authority,
       TOKEN_PROGRAM_SPL,
       6,
       0,
       TOKEN_ORACLE_PLAIN_TRANSFER,
       {0}},
  };
  token_oracle_install(oracle, sizeof(oracle) / sizeof(oracle[0]));
  sbpf_runtime_initialize();

  klee_make_symbolic(&record_owner, sizeof(record_owner), "record.owner");
  klee_make_symbolic(&requested_amount, sizeof(requested_amount),
                     "record.data.amount");
#ifdef PROCESS_INSTRUCTION_SYMBOLIC_SELECTOR
  klee_make_symbolic(&instruction_selector, sizeof(instruction_selector),
                     "instruction.selector");
#endif
  klee_assume(record_owner.words[0] != program_id.words[0]);
  memcpy(record_data, &requested_amount, sizeof(requested_amount));

  const struct asset_balance_view source_view = {&accounts[1],
                                                 ASSET_BALANCE_TOKEN_AMOUNT};
  const struct asset_balance_view destination_view = {
      &accounts[2], ASSET_BALANCE_TOKEN_AMOUNT};
  const uint64_t source_before = asset_balance_read(source_view);
  const uint64_t destination_before = asset_balance_read(destination_view);

  registers[1] = (uint64_t)(uintptr_t)result;
  registers[2] = (uint64_t)(uintptr_t)&program_id;
  registers[3] = (uint64_t)(uintptr_t)accounts;
  registers[4] = 5;
#ifdef PROCESS_INSTRUCTION_SELECTOR
  prepare_process_instruction_call(registers, &dispatcher_frame,
                                   &instruction_selector, 1);
#endif
  (void)bpf_main(registers, sizeof(registers));

  if (lifted_program_succeeded(result) &&
      asset_transfer_observed(source_before, asset_balance_read(source_view),
                              destination_before,
                              asset_balance_read(destination_view))) {
    klee_assert(token_model_transfer_attempts() == 1);
    klee_assert(token_model_transfers_committed() == 1);
    klee_assert(!pubkeys_equal(&record_owner, &program_id));
    klee_report_error(__FILE__, __LINE__,
                      "SPL tokens transferred from an unowned record",
                      "unauthorized-token-transfer.err");
  }

  token_oracle_reset();
  return 0;
}
