#include <assert.h>
#include <stdint.h>

#include <klee/klee.h>

#include "asset_model.h"

extern uint64_t bpf_main(void *register_context, uint64_t context_size);

// Negative control: a valid-looking SPL Transfer must not mutate a non-token-classified account.
int main(void) {
  uint64_t registers[10] = {0};
  uint64_t result[3] = {0};
  struct pubkey program_id = {{UINT64_C(0x42), 0, 0, 0}};
  struct pubkey record_owner = {{UINT64_C(0x43), 0, 0, 0}};
  struct pubkey mint = {{UINT64_C(0x77), 0, 0, 0}};
  struct pubkey source_authority = {{UINT64_C(0x88), 0, 0, 0}};
  struct pubkey destination_authority = {{UINT64_C(0x99), 0, 0, 0}};
  struct pubkey keys[5] = {{{1, 0, 0, 0}},
                           {{2, 0, 0, 0}},
                           {{3, 0, 0, 0}},
                           {{UINT64_C(0x88), 0, 0, 0}},
                           {{0}}};
  uint8_t record_data[8] = {1};
  uint8_t source_data[TOKEN_ACCOUNT_BASE_LENGTH];
  uint8_t destination_data[TOKEN_ACCOUNT_BASE_LENGTH];
  uint8_t empty_data = 0;
  uint64_t lamports[5] = {1, 1, 1, 1, 1};
  struct rc_refcell_u64 lamports_rc[5];
  struct rc_refcell_slice data_rc[5];
  struct account_info accounts[5] = {0};

  keys[4] = SPL_TOKEN_PROGRAM_ID;
  initialize_token_account_data(source_data, &mint, &source_authority, 100);
  initialize_token_account_data(destination_data, &mint,
                                &destination_authority, 10);

  for (unsigned index = 0; index < 5; ++index) {
    lamports_rc[index] =
        (struct rc_refcell_u64){1, 1, 0, &lamports[index]};
    data_rc[index] =
        (struct rc_refcell_slice){1, 1, 0, &empty_data, 0};
    accounts[index].key = &keys[index];
    accounts[index].lamports = &lamports_rc[index];
    accounts[index].data = &data_rc[index];
  }
  data_rc[0] = (struct rc_refcell_slice){1, 1, 0, record_data,
                                        sizeof(record_data)};
  data_rc[1] = (struct rc_refcell_slice){1, 1, 0, source_data,
                                        sizeof(source_data)};
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

  // Deliberately omit destination from the oracle.
  const struct token_account_oracle_entry oracle[] = {{
      &accounts[1], &mint, &source_authority, TOKEN_PROGRAM_SPL, 6, 0,
      TOKEN_ORACLE_PLAIN_TRANSFER, {0}}};
  token_oracle_install(oracle, 1);
  sbpf_runtime_initialize();

  const struct asset_balance_view source_view = {
      &accounts[1], ASSET_BALANCE_TOKEN_AMOUNT};
  const struct asset_balance_view destination_view = {
      &accounts[2], ASSET_BALANCE_TOKEN_AMOUNT};
  const uint64_t source_before = asset_balance_read(source_view);
  const uint64_t destination_before = asset_balance_read(destination_view);

  registers[1] = (uint64_t)(uintptr_t)result;
  registers[2] = (uint64_t)(uintptr_t)&program_id;
  registers[3] = (uint64_t)(uintptr_t)accounts;
  registers[4] = 5;
  (void)bpf_main(registers, sizeof(registers));

  klee_assert(token_model_transfer_attempts() == 1);
  klee_assert(token_model_transfers_committed() == 0);
  klee_assert(!lifted_program_succeeded(result));
  klee_assert(asset_balance_read(source_view) == source_before);
  klee_assert(asset_balance_read(destination_view) == destination_before);
  token_oracle_reset();
  return 0;
}
