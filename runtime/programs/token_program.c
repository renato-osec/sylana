/* Abstract program: SPL Token and Token-2022. Models Transfer, TransferChecked,
 * MintTo, Burn and their Checked variants. Token accounts come from a concrete
 * per-account oracle when a harness installs one, else from the account's own
 * (concrete, fetched) data. Only amounts reach the solver. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <klee/klee.h>

#include "programs/programs.h"

// SPL Token / Token-2022 instruction discriminants (a leading u8 tag). Order
// matches spl_token::instruction::TokenInstruction.
enum TokenInstructionDisc {
  InitializeMint = 0,
  InitializeAccount = 1,
  InitializeMultisig = 2,
  Transfer = 3,
  Approve = 4,
  Revoke = 5,
  SetAuthority = 6,
  MintTo = 7,
  Burn = 8,
  CloseAccount = 9,
  FreezeAccount = 10,
  ThawAccount = 11,
  TransferChecked = 12,
  MintToChecked = 14,
  BurnChecked = 15,
  ScaledUiAmountExtension = 43,
};

// Token-2022 TLV extensions follow the 165-byte base and an account-type byte.
enum {
  EXTENSION_ACCOUNT_TYPE_OFFSET = 165,
  EXTENSION_TLV_OFFSET = 166,
  EXTENSION_TYPE_SCALED_UI_AMOUNT = 25,
  // ScaledUiAmountConfig: authority(32) multiplier(f64) effective_timestamp(i64) new_multiplier(f64)
  SCALED_UI_MULTIPLIER_OFFSET = 32,
  SCALED_UI_EFFECTIVE_TIMESTAMP_OFFSET = 40,
  SCALED_UI_NEW_MULTIPLIER_OFFSET = 48,
  SCALED_UI_CONFIG_LENGTH = 56,
};

// SPL Mint layout: COption<Pubkey> mint_authority (4 + 32), u64 supply,
// u8 decimals, u8 is_initialized, COption<Pubkey> freeze_authority.
enum {
  MINT_AUTHORITY_TAG_OFFSET = 0,
  MINT_AUTHORITY_OFFSET = 4,
  MINT_SUPPLY_OFFSET = 36,
  MINT_DECIMALS_OFFSET = 44,
  MINT_INITIALIZED_OFFSET = 45,
  MINT_LENGTH = 82,
};

static const struct token_account_oracle_entry *token_oracle_entries;
static uint64_t token_oracle_count;
static uint64_t token_transfer_attempts;
static uint64_t token_transfers_committed;

void token_model_reset(void) {
  token_transfer_attempts = 0;
  token_transfers_committed = 0;
}

uint64_t token_model_transfer_attempts(void) { return token_transfer_attempts; }

uint64_t token_model_transfers_committed(void) {
  return token_transfers_committed;
}

void token_oracle_install(const struct token_account_oracle_entry *entries,
                          uint64_t count) {
  /* A concrete small table keeps lookup bounded and solver-independent. */
  if (count > 32) {
    klee_report_error(__FILE__, __LINE__, "token oracle is too large",
                      "oracle.err");
  }
  token_oracle_entries = entries;
  token_oracle_count = count;
}

void token_oracle_reset(void) {
  token_oracle_entries = NULL;
  token_oracle_count = 0;
}

enum token_program_kind token_program_kind_for_id(const struct pubkey *program_id) {
  if (pubkeys_equal(program_id, &SPL_TOKEN_PROGRAM_ID)) {
    return TOKEN_PROGRAM_SPL;
  }
  if (pubkeys_equal(program_id, &TOKEN_2022_PROGRAM_ID)) {
    return TOKEN_PROGRAM_2022;
  }
  return TOKEN_PROGRAM_NONE;
}

static const struct token_account_oracle_entry *
token_oracle_find(const uint8_t key[32], enum token_program_kind program_kind) {
  for (uint64_t index = 0; index < token_oracle_count; ++index) {
    const struct token_account_oracle_entry *entry =
        &token_oracle_entries[index];
    if (entry->program_kind == program_kind && entry->account != NULL &&
        entry->account->key != NULL &&
        pubkey_bytes_equal(key, entry->account->key)) {
      return entry;
    }
  }
  return NULL;
}

static int
token_account_matches_oracle(const struct account_info *account,
                             const struct token_account_oracle_entry *entry,
                             const struct pubkey *token_program) {
  if (account == NULL || entry == NULL || entry->account == NULL ||
      account->data == NULL || entry->account->data == NULL ||
      account->owner == NULL || !pubkeys_equal(account->owner, token_program) ||
      account->data->data == NULL || entry->account->data->data == NULL ||
      account->data->length != entry->account->data->length ||
      account->data->length < TOKEN_ACCOUNT_BASE_LENGTH ||
      account->data->data[TOKEN_ACCOUNT_STATE_OFFSET] != 1 ||
      entry->mint == NULL ||
      !pubkey_bytes_equal(account->data->data + TOKEN_ACCOUNT_MINT_OFFSET,
                          entry->mint)) {
    return 0;
  }
  for (uint64_t index = 0; index < account->data->length; ++index) {
    if (account->data->data[index] != entry->account->data->data[index]) {
      return 0;
    }
  }
  return 1;
}


/* A token account as the model sees it. An installed oracle (hand harnesses) is
 * authoritative; otherwise the account's own concrete data is: mint at 0, owner
 * at 32, amount at 64, state at 108. Returns NULL when the account is not a
 * valid, initialized token account of `program`. */
static const struct token_account_oracle_entry *
token_view(const struct account_info *account, const uint8_t key[32],
           enum token_program_kind program_kind, const struct pubkey *program,
           struct token_account_oracle_entry *scratch, struct pubkey *mint,
           struct pubkey *authority) {
  if (token_oracle_count != 0) {
    const struct token_account_oracle_entry *entry =
        token_oracle_find(key, program_kind);
    if (entry == NULL) {
      klee_report_error(__FILE__, __LINE__, "token account missing from oracle",
                        "oracle.err");
    }
    if (account == NULL) {
      klee_report_error(__FILE__, __LINE__, "CPI account is unavailable",
                        "cpi-runtime.err");
    }
    return token_account_matches_oracle(account, entry, program) ? entry : NULL;
  }
  if (account == NULL || account->data == NULL || account->data->data == NULL) {
    klee_report_error(__FILE__, __LINE__, "CPI account is unavailable",
                      "cpi-runtime.err");
  }
  if (account->owner == NULL || !pubkeys_equal(account->owner, program) ||
      account->data->length < TOKEN_ACCOUNT_BASE_LENGTH ||
      account->data->data[TOKEN_ACCOUNT_STATE_OFFSET] != 1) {
    return NULL;
  }
  memcpy(mint, account->data->data + TOKEN_ACCOUNT_MINT_OFFSET, sizeof(*mint));
  memcpy(authority, account->data->data + TOKEN_ACCOUNT_OWNER_OFFSET,
         sizeof(*authority));
  scratch->account = account;
  scratch->mint = mint;
  scratch->authority = authority; /* ponytail: delegates are not modeled */
  scratch->program_kind = (uint8_t)program_kind;
  scratch->decimals = 0xff; /* unknown here; checked against the mint */
  scratch->authority_is_pda = 1; /* ponytail: invoke_signed seeds are trusted */
  /* ponytail: Token-2022 extensions (transfer fees, hooks) are not modeled */
  scratch->flags = TOKEN_ORACLE_PLAIN_TRANSFER;
  return scratch;
}

/* The mint account behind MintTo/Burn/Checked: owner, initialization, and
 * (when `decimals` != 0xff) the caller's decimals must match. */
static uint64_t mint_view(const struct account_info *account,
                          const struct pubkey *program, uint8_t decimals) {
  if (account == NULL || account->data == NULL || account->data->data == NULL) {
    klee_report_error(__FILE__, __LINE__, "CPI mint account is unavailable",
                      "cpi-runtime.err");
  }
  if (account->owner == NULL || !pubkeys_equal(account->owner, program)) {
    return cpi_program_failure("incorrect mint program owner",
                               CPI_BUILTIN(PROGRAM_ERROR_INCORRECT_PROGRAM_ID));
  }
  if (account->data->length < MINT_LENGTH) {
    return cpi_program_failure("invalid mint account data",
                               CPI_CUSTOM(TOKEN_INVALID_MINT));
  }
  if (account->data->data[MINT_INITIALIZED_OFFSET] != 1) {
    return cpi_program_failure("uninitialized mint account",
                               CPI_CUSTOM(TOKEN_UNINITIALIZED_STATE));
  }
  if (decimals != 0xff && account->data->data[MINT_DECIMALS_OFFSET] != decimals) {
    return cpi_program_failure("token mint decimals mismatch",
                               CPI_CUSTOM(TOKEN_MINT_DECIMALS_MISMATCH));
  }
  return CPI_SUCCESS;
}

/* The meta must be a signer for `expected`; a PDA authority signs via seeds. */
static uint64_t require_authority(const struct stable_account_meta *meta,
                                  const struct account_info *authority,
                                  const uint8_t expected[32], int is_pda,
                                  uint64_t signers_seeds_len) {
  if (!meta->is_signer) {
    return cpi_program_failure("missing token authority signature",
                               CPI_BUILTIN(PROGRAM_ERROR_MISSING_REQUIRED_SIGNATURES));
  }
  if (!pubkey_bytes_equal(meta->key, expected)) {
    return cpi_program_failure("token authority mismatch",
                               CPI_CUSTOM(TOKEN_OWNER_MISMATCH));
  }
  if (authority == NULL) {
    klee_report_error(__FILE__, __LINE__, "CPI account is unavailable",
                      "cpi-runtime.err");
  }
  if (!authority->is_signer && !(is_pda && signers_seeds_len > 0)) {
    klee_report_error(__FILE__, __LINE__, "CPI signer privilege escalation",
                      "cpi-runtime.err");
  }
  return CPI_SUCCESS;
}

static uint64_t account_amount(const struct account_info *account) {
  return token_load_u64(account->data->data + TOKEN_ACCOUNT_AMOUNT_OFFSET);
}

static void set_account_amount(const struct account_info *account, uint64_t v) {
  token_store_u64(account->data->data + TOKEN_ACCOUNT_AMOUNT_OFFSET, v);
}

/* The value bytes of TLV extension `type` in a Token-2022 mint, or NULL. */
static uint8_t *find_extension(const struct account_info *mint, uint16_t type,
                               uint16_t min_length) {
  uint8_t *data = mint->data->data;
  uint64_t length = mint->data->length;
  uint64_t position = EXTENSION_TLV_OFFSET;
  if (length <= EXTENSION_ACCOUNT_TYPE_OFFSET ||
      data[EXTENSION_ACCOUNT_TYPE_OFFSET] != 1 /* AccountType::Mint */) {
    return NULL;
  }
  while (position + 4 <= length) {
    uint16_t entry_type = (uint16_t)(data[position] | data[position + 1] << 8);
    uint16_t entry_length = (uint16_t)(data[position + 2] | data[position + 3] << 8);
    if (entry_type == 0) break;
    if (entry_type == type) {
      return entry_length >= min_length && position + 4 + entry_length <= length
                 ? data + position + 4
                 : NULL;
    }
    position += 4 + entry_length;
  }
  return NULL;
}

/* Token-2022 ScaledUiAmountExtension::UpdateMultiplier {new_multiplier: f64,
 * effective_timestamp: i64}, accounts [mint, authority]. A multiplier dated in
 * the past applies now; either way it is scheduled on the config. */
static uint64_t scaled_ui_amount_cpi(const struct stable_instruction *instruction,
                                     const struct account_info *account_infos,
                                     uint64_t account_infos_len,
                                     uint64_t signers_seeds_len) {
  const uint8_t *data = (const uint8_t *)instruction->data.pointer;
  const struct stable_account_meta *metas =
      (const struct stable_account_meta *)instruction->accounts.pointer;
  const struct account_info *mint;
  uint8_t *config;
  double new_multiplier;
  int64_t effective_timestamp;
  uint64_t error;

  if (instruction->data.length < 2 || data[1] != 1 /* UpdateMultiplier */) {
    klee_report_error(__FILE__, __LINE__,
                      "unmodeled ScaledUiAmount extension instruction", "cpi.err");
  }
  if (instruction->data.length < 18 || instruction->accounts.length < 2) {
    return cpi_program_failure("invalid UpdateMultiplier instruction", CPI_BUILTIN(PROGRAM_ERROR_INVALID_INSTRUCTION_DATA));
  }
  if (!metas[0].is_writable) {
    klee_report_error(__FILE__, __LINE__, "CPI writes a readonly account",
                      "cpi-runtime.err");
  }
  mint = cpi_find_account(account_infos, account_infos_len, metas[0].key);
  if ((error = mint_view(mint, &instruction->program_id, 0xff)) != CPI_SUCCESS) {
    return error;
  }
  config = find_extension(mint, EXTENSION_TYPE_SCALED_UI_AMOUNT, SCALED_UI_CONFIG_LENGTH);
  if (config == NULL) {
    return cpi_program_failure("mint has no ScaledUiAmount extension", CPI_BUILTIN(PROGRAM_ERROR_INVALID_ACCOUNT_DATA));
  }
  error = require_authority(
      &metas[1], cpi_find_account(account_infos, account_infos_len, metas[1].key),
      config, 1, signers_seeds_len);
  if (error != CPI_SUCCESS) return error;
  memcpy(&new_multiplier, data + 2, sizeof(new_multiplier));
  memcpy(&effective_timestamp, data + 10, sizeof(effective_timestamp));
  /* positive and finite (NaN and infinity fail these without math.h) */
  if (!(new_multiplier > 0.0) || new_multiplier - new_multiplier != 0.0) {
    return cpi_program_failure("invalid scaled UI multiplier", CPI_BUILTIN(PROGRAM_ERROR_INVALID_ARGUMENT));
  }
  if (effective_timestamp <= sbpf_runtime_unix_timestamp()) {
    memcpy(config + SCALED_UI_MULTIPLIER_OFFSET, data + 2, 8);
  }
  memcpy(config + SCALED_UI_EFFECTIVE_TIMESTAMP_OFFSET, data + 10, 8);
  memcpy(config + SCALED_UI_NEW_MULTIPLIER_OFFSET, data + 2, 8);
  return CPI_SUCCESS;
}

uint64_t token_program_cpi(const struct stable_instruction *instruction,
                           const struct account_info *account_infos,
                           uint64_t account_infos_len,
                           enum token_program_kind program_kind,
                           uint64_t signers_seeds_len) {
  const struct pubkey *program = &instruction->program_id;
  const struct stable_account_meta *metas;
  const uint8_t *data;
  const struct stable_account_meta *a_meta;
  const struct stable_account_meta *b_meta;
  const struct stable_account_meta *authority_meta;
  const struct stable_account_meta *mint_meta = NULL;
  const struct account_info *a;
  const struct account_info *b;
  const struct account_info *authority;
  struct token_account_oracle_entry scratch_a;
  struct token_account_oracle_entry scratch_b;
  struct pubkey mint_a, authority_a, mint_b, authority_b;
  const struct token_account_oracle_entry *view_a;
  const struct token_account_oracle_entry *view_b = NULL;
  uint8_t tag;
  uint8_t decimals = 0xff;
  uint64_t amount;
  uint64_t error;
  enum { OP_TRANSFER, OP_MINT_TO, OP_BURN } op;

  data = (const uint8_t *)instruction->data.pointer;
  if (program_kind == TOKEN_PROGRAM_2022 && instruction->data.length >= 1 &&
      data[0] == ScaledUiAmountExtension) {
    return scaled_ui_amount_cpi(instruction, account_infos, account_infos_len,
                                signers_seeds_len);
  }
  if (instruction->data.length < 9) {
    return cpi_program_failure("invalid token instruction data", CPI_BUILTIN(PROGRAM_ERROR_INVALID_INSTRUCTION_DATA));
  }
  metas = (const struct stable_account_meta *)instruction->accounts.pointer;
  for (uint64_t index = 0; index < instruction->accounts.length; ++index) {
    if (metas[index].is_signer > 1 || metas[index].is_writable > 1) {
      klee_report_error(__FILE__, __LINE__, "invalid CPI AccountMeta boolean",
                        "syscall.err");
    }
  }
  tag = data[0];
  amount = token_load_u64(data + 1);

  /* Account order per spl_token: Transfer [src, dst, auth];
   * TransferChecked [src, mint, dst, auth]; MintTo(Checked) [mint, dst, auth];
   * Burn(Checked) [src, mint, auth]. Checked variants carry decimals at 9. */
  switch ((enum TokenInstructionDisc)tag) {
  case Transfer:
    if (instruction->accounts.length < 3) {
      return cpi_program_failure("not enough token CPI accounts", CPI_BUILTIN(PROGRAM_ERROR_NOT_ENOUGH_ACCOUNT_KEYS));
    }
    op = OP_TRANSFER;
    a_meta = &metas[0]; b_meta = &metas[1]; authority_meta = &metas[2];
    break;
  case TransferChecked:
    if (instruction->data.length < 10 || instruction->accounts.length < 4) {
      return cpi_program_failure("invalid TransferChecked instruction", CPI_BUILTIN(PROGRAM_ERROR_INVALID_INSTRUCTION_DATA));
    }
    op = OP_TRANSFER;
    decimals = data[9];
    a_meta = &metas[0]; mint_meta = &metas[1]; b_meta = &metas[2];
    authority_meta = &metas[3];
    break;
  case MintTo:
  case MintToChecked:
    if (instruction->accounts.length < 3 ||
        (tag == MintToChecked && instruction->data.length < 10)) {
      return cpi_program_failure("invalid MintTo instruction", CPI_BUILTIN(PROGRAM_ERROR_INVALID_INSTRUCTION_DATA));
    }
    op = OP_MINT_TO;
    if (tag == MintToChecked) decimals = data[9];
    mint_meta = &metas[0]; a_meta = &metas[1]; authority_meta = &metas[2];
    break;
  case Burn:
  case BurnChecked:
    if (instruction->accounts.length < 3 ||
        (tag == BurnChecked && instruction->data.length < 10)) {
      return cpi_program_failure("invalid Burn instruction", CPI_BUILTIN(PROGRAM_ERROR_INVALID_INSTRUCTION_DATA));
    }
    op = OP_BURN;
    if (tag == BurnChecked) decimals = data[9];
    a_meta = &metas[0]; mint_meta = &metas[1]; authority_meta = &metas[2];
    break;
  default: {
    static char message[] = "unmodeled token CPI instruction tag=000";
    message[sizeof(message) - 4] = (char)('0' + tag / 100);
    message[sizeof(message) - 3] = (char)('0' + tag / 10 % 10);
    message[sizeof(message) - 2] = (char)('0' + tag % 10);
    klee_report_error(__FILE__, __LINE__, message, "cpi.err");
  }
  }

  if (!a_meta->is_writable || (op == OP_TRANSFER && !b_meta->is_writable) ||
      (op != OP_TRANSFER && !mint_meta->is_writable)) {
    klee_report_error(__FILE__, __LINE__, "CPI writes a readonly account",
                      "cpi-runtime.err");
  }

  a = cpi_find_account(account_infos, account_infos_len, a_meta->key);
  authority = cpi_find_account(account_infos, account_infos_len, authority_meta->key);
  view_a = token_view(a, a_meta->key, program_kind, program, &scratch_a,
                      &mint_a, &authority_a);
  if (view_a == NULL) {
    return cpi_program_failure("token account validation failed", CPI_CUSTOM(TOKEN_UNINITIALIZED_STATE));
  }
  if (op == OP_TRANSFER) {
    b = cpi_find_account(account_infos, account_infos_len, b_meta->key);
    view_b = token_view(b, b_meta->key, program_kind, program, &scratch_b,
                        &mint_b, &authority_b);
    if (view_b == NULL) {
      return cpi_program_failure("token account validation failed", CPI_CUSTOM(TOKEN_UNINITIALIZED_STATE));
    }
    if (!(view_a->flags & TOKEN_ORACLE_PLAIN_TRANSFER) ||
        !(view_b->flags & TOKEN_ORACLE_PLAIN_TRANSFER)) {
      klee_report_error(__FILE__, __LINE__, "token extensions are not modeled",
                        "cpi.err");
    }
    if (!pubkeys_equal(view_a->mint, view_b->mint)) {
      return cpi_program_failure("token mint mismatch", CPI_CUSTOM(TOKEN_MINT_MISMATCH));
    }
  }
  if (mint_meta != NULL && !pubkey_bytes_equal(mint_meta->key, view_a->mint)) {
    return cpi_program_failure("token mint mismatch", CPI_CUSTOM(TOKEN_MINT_MISMATCH));
  }
  if (view_a->decimals != 0xff && decimals != 0xff && view_a->decimals != decimals) {
    return cpi_program_failure("token mint decimals mismatch", CPI_CUSTOM(TOKEN_MINT_DECIMALS_MISMATCH));
  }

  if (op == OP_MINT_TO) {
    const struct account_info *mint =
        cpi_find_account(account_infos, account_infos_len, mint_meta->key);
    const uint8_t *mint_data;
    uint64_t supply, balance;
    if ((error = mint_view(mint, program, decimals)) != CPI_SUCCESS) return error;
    mint_data = mint->data->data;
    supply = token_load_u64(mint_data + MINT_SUPPLY_OFFSET);
    balance = account_amount(a);
    if (token_load_u64(mint_data + MINT_AUTHORITY_TAG_OFFSET) % 0x100000000ULL != 1) {
      return cpi_program_failure("mint has no mint authority",
                                 CPI_CUSTOM(TOKEN_FIXED_SUPPLY));
    }
    error = require_authority(authority_meta, authority,
                              mint_data + MINT_AUTHORITY_OFFSET, 1, signers_seeds_len);
    if (error != CPI_SUCCESS) return error;
    if (UINT64_MAX - balance < amount || UINT64_MAX - supply < amount) {
      return cpi_program_failure("token amount overflow", CPI_CUSTOM(TOKEN_OVERFLOW));
    }
    set_account_amount(a, balance + amount);
    token_store_u64(mint->data->data + MINT_SUPPLY_OFFSET, supply + amount);
    return CPI_SUCCESS;
  }

  if (view_a->authority == NULL) {
    klee_report_error(__FILE__, __LINE__, "oracle has no token authority",
                      "oracle.err");
  }
  error = require_authority(authority_meta, authority,
                            (const uint8_t *)view_a->authority,
                            view_a->authority_is_pda, signers_seeds_len);
  if (error != CPI_SUCCESS) return error;

  if (op == OP_BURN) {
    const struct account_info *mint =
        cpi_find_account(account_infos, account_infos_len, mint_meta->key);
    uint64_t supply, balance;
    if ((error = mint_view(mint, program, decimals)) != CPI_SUCCESS) return error;
    supply = token_load_u64(mint->data->data + MINT_SUPPLY_OFFSET);
    balance = account_amount(a);
    if (amount > balance || amount > supply) {
      return cpi_program_failure("insufficient token funds",
                                 CPI_CUSTOM(TOKEN_INSUFFICIENT_FUNDS));
    }
    set_account_amount(a, balance - amount);
    token_store_u64(mint->data->data + MINT_SUPPLY_OFFSET, supply - amount);
    return CPI_SUCCESS;
  }

  /* Transfer. */
  ++token_transfer_attempts;
  if (mint_meta != NULL) {
    error = mint_view(cpi_find_account(account_infos, account_infos_len, mint_meta->key),
                      program, decimals);
    if (error != CPI_SUCCESS) return error;
    if (view_b->decimals != 0xff && view_b->decimals != decimals) {
      return cpi_program_failure("token mint decimals mismatch", CPI_CUSTOM(TOKEN_MINT_DECIMALS_MISMATCH));
    }
  }
  {
    uint64_t source_amount = account_amount(a);
    uint64_t destination_amount = account_amount(b);
    if (amount > source_amount) {
      return cpi_program_failure("insufficient token funds", CPI_CUSTOM(TOKEN_INSUFFICIENT_FUNDS));
    }
    /* A self-transfer succeeds after validation but has no net balance effect. */
    if (a->data == b->data) {
      return CPI_SUCCESS;
    }
    if (UINT64_MAX - destination_amount < amount) {
      return cpi_program_failure("token amount overflow", CPI_CUSTOM(TOKEN_OVERFLOW));
    }
    set_account_amount(a, source_amount - amount);
    set_account_amount(b, destination_amount + amount);
  }
  if (amount != 0) {
    ++token_transfers_committed;
  }
  return CPI_SUCCESS;
}
