#ifndef OWNER_CHECK_ASSET_MODEL_H
#define OWNER_CHECK_ASSET_MODEL_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "account_model.h"

enum token_program_kind {
  TOKEN_PROGRAM_NONE = 0, // program_id is not a modeled token program
  TOKEN_PROGRAM_SPL = 1,
  TOKEN_PROGRAM_2022 = 2,
};

enum token_oracle_flags {
  // Oracle certifies no Token-2022 extension alters transfer amounts or adds a hook side effect
  TOKEN_ORACLE_PLAIN_TRANSFER = 1,
};

static const struct pubkey SPL_TOKEN_PROGRAM_ID = {
    {UINT64_C(0x93a165d7e1f6dd06), UINT64_C(0xac79ebce46e1cbd9),
     UINT64_C(0x91375b5fed85b41c), UINT64_C(0xa900ff7e85f58c3a)}};

static const struct pubkey TOKEN_2022_PROGRAM_ID = {
    {UINT64_C(0xde8f75eee1f6dd06), UINT64_C(0xdacd6ce4bc5d4218),
     UINT64_C(0x270db9834dfc1ab6), UINT64_C(0xfc8ba1d828f9bdfe)}};

// The System program's id is the all-zero pubkey.
static const struct pubkey SYSTEM_PROGRAM_ID = {{0, 0, 0, 0}};

// Canonical values the sysvar syscalls return, so sysvar reads are consistent.
enum {
  SYLANA_CLOCK_SLOT = 100,
  SYLANA_CLOCK_EPOCH = 10,
  SYLANA_CLOCK_UNIX_TIMESTAMP = 1700000000,
  SYLANA_RENT_LAMPORTS_PER_BYTE_YEAR = 3480,
  SYLANA_RENT_BURN_PERCENT = 50,
};

// StableInstruction and AccountMeta as passed to sol_invoke_signed_rust
struct stable_vec {
  void *pointer;
  uint64_t capacity;
  uint64_t length;
};

struct stable_account_meta {
  uint8_t key[32];
  uint8_t is_signer;
  uint8_t is_writable;
};

struct stable_instruction {
  struct stable_vec accounts;
  struct stable_vec data;
  struct pubkey program_id;
};

_Static_assert(sizeof(struct stable_vec) == 24,
               "unexpected StableVec ABI");
_Static_assert(sizeof(struct stable_account_meta) == 34,
               "unexpected AccountMeta ABI");
_Static_assert(offsetof(struct stable_instruction, data) == 24,
               "unexpected StableInstruction.data offset");
_Static_assert(offsetof(struct stable_instruction, program_id) == 48,
               "unexpected StableInstruction.program_id offset");
_Static_assert(sizeof(struct stable_instruction) == 80,
               "unexpected StableInstruction ABI");

// SPL Token and Token-2022 share this fixed base-account prefix
enum {
  TOKEN_ACCOUNT_MINT_OFFSET = 0,
  TOKEN_ACCOUNT_OWNER_OFFSET = 32,
  TOKEN_ACCOUNT_AMOUNT_OFFSET = 64,
  TOKEN_ACCOUNT_STATE_OFFSET = 108,
  TOKEN_ACCOUNT_BASE_LENGTH = 165,
};

// Concrete stand-in for the future static-analysis oracle; keyed by account so it survives CPI clones
// authority = resolved transfer authority (owner or delegate), without decoding delegate state
struct token_account_oracle_entry {
  const struct account_info *account;
  const struct pubkey *mint;
  const struct pubkey *authority;
  uint8_t program_kind;
  uint8_t decimals;
  uint8_t authority_is_pda;
  uint8_t flags;
  uint8_t reserved[4];
};

void token_oracle_install(const struct token_account_oracle_entry *entries,
                          uint64_t count);
void token_oracle_reset(void);
void sbpf_runtime_initialize(void);
uint64_t token_model_transfer_attempts(void);
uint64_t token_model_transfers_committed(void);
uint64_t sbpf_runtime_sha256_calls(void);
uint64_t sbpf_runtime_log_format_summaries(void);
uint64_t sbpf_runtime_recorded_calls(void);
void sbpf_runtime_map_readonly(void *guest_address, const void *contents,
                               uint64_t length);
void sbpf_runtime_map_readonly_regions(void *guest_address,
                                       const void *contents,
                                       const uint64_t *region_ends,
                                       uint64_t region_count);

struct sbpf_runtime_clock {
  uint64_t slot;
  int64_t epoch_start_timestamp;
  uint64_t epoch;
  uint64_t leader_schedule_epoch;
  int64_t unix_timestamp;
};

struct sbpf_runtime_rent {
  uint64_t lamports_per_byte_year;
  double exemption_threshold;
  uint8_t burn_percent;
  uint8_t padding[7];
};

void sbpf_runtime_set_clock(const struct sbpf_runtime_clock *clock);
void sbpf_runtime_set_rent(const struct sbpf_runtime_rent *rent);
int64_t sbpf_runtime_unix_timestamp(void);
void pda_oracle_install(const struct pubkey *keys, uint64_t count);

/* Tail of the program's sol_log_ output; harnesses export it as "log". */
#define SBPF_LOG_TAIL_BYTES 1024
extern char sbpf_log_tail[SBPF_LOG_TAIL_BYTES];
void sbpf_runtime_log(const char *text);

enum asset_balance_kind {
  ASSET_BALANCE_LAMPORTS = 1,
  ASSET_BALANCE_TOKEN_AMOUNT = 2,
};

struct asset_balance_view {
  const struct account_info *account;
  uint8_t kind;
};

static inline uint64_t token_load_u64(const uint8_t *bytes) {
  uint64_t value = 0;
  for (unsigned index = 0; index < 8; ++index) {
    value |= (uint64_t)bytes[index] << (index * 8);
  }
  return value;
}

static inline int pubkey_bytes_equal(const uint8_t bytes[32],
                                     const struct pubkey *key) {
  const uint8_t *key_bytes = (const uint8_t *)key;
  for (unsigned index = 0; index < 32; ++index) {
    if (bytes[index] != key_bytes[index]) {
      return 0;
    }
  }
  return 1;
}

static inline void token_store_u64(uint8_t *bytes, uint64_t value) {
  for (unsigned index = 0; index < 8; ++index) {
    bytes[index] = (uint8_t)(value >> (index * 8));
  }
}

static inline uint64_t asset_balance_read(struct asset_balance_view view) {
  if (view.kind == ASSET_BALANCE_LAMPORTS) {
    return *view.account->lamports->value;
  }
  return token_load_u64(view.account->data->data + TOKEN_ACCOUNT_AMOUNT_OFFSET);
}

static inline int asset_transfer_observed(uint64_t source_before,
                                          uint64_t source_after,
                                          uint64_t destination_before,
                                          uint64_t destination_after) {
  return source_after < source_before && destination_after > destination_before &&
         source_before - source_after == destination_after - destination_before;
}

// Lifted-SDK ProgramResult; mutations commit only when the analyzed function returns Ok
static inline int lifted_program_succeeded(const uint64_t result[3]) {
  // Niche encoding of Ok(()) for Result<(), ProgramError>: discriminants 0..25, first invalid niche is 26
  return result[0] == UINT64_C(0x800000000000001a);
}

static inline void initialize_token_account_data(
    uint8_t data[TOKEN_ACCOUNT_BASE_LENGTH], const struct pubkey *mint,
    const struct pubkey *authority, uint64_t amount) {
  memset(data, 0, TOKEN_ACCOUNT_BASE_LENGTH);
  memcpy(data + TOKEN_ACCOUNT_MINT_OFFSET, mint, sizeof(*mint));
  memcpy(data + TOKEN_ACCOUNT_OWNER_OFFSET, authority, sizeof(*authority));
  token_store_u64(data + TOKEN_ACCOUNT_AMOUNT_OFFSET, amount);
  data[TOKEN_ACCOUNT_STATE_OFFSET] = 1; // AccountState::Initialized
}

#endif
