/* Abstract program: System. Models SOL transfers and basic account creation;
 * moves lamports and sets owners faithfully. Account data/space growth is not
 * modeled. ponytail: source system-ownership is not checked; add it if a
 * program relies on System rejecting a non-system-owned source. */
#include <stdint.h>
#include <string.h>

#include <klee/klee.h>

#include "programs/programs.h"

// SystemInstruction bincode discriminants (a leading u32 tag). Order matches
// solana_program::system_instruction::SystemInstruction. Only the variants
// below are modeled; the rest fall through to the unmodeled path.
enum SystemInstructionDisc {
  CreateAccount = 0,
  Assign = 1,
  Transfer = 2,
  CreateAccountWithSeed = 3,
  AdvanceNonceAccount = 4,
  WithdrawNonceAccount = 5,
  InitializeNonceAccount = 6,
  AuthorizeNonceAccount = 7,
  Allocate = 8,
  AllocateWithSeed = 9,
  AssignWithSeed = 10,
  TransferWithSeed = 11,
  UpgradeNonceAccount = 12,
};

// Solana's absolute per-account data cap (10 MiB).
enum { MAX_PERMITTED_DATA_LENGTH = 10 * 1024 * 1024 };

uint64_t system_program_cpi(const struct stable_instruction *instruction,
                            const struct account_info *account_infos,
                            uint64_t account_infos_len) {
  const uint8_t *data = (const uint8_t *)instruction->data.pointer;
  const struct stable_account_meta *metas =
      (const struct stable_account_meta *)instruction->accounts.pointer;
  if (instruction->data.length < 4) {
    return cpi_program_failure("invalid system instruction data", CPI_BUILTIN(PROGRAM_ERROR_INVALID_INSTRUCTION_DATA));
  }
  enum SystemInstructionDisc tag = (enum SystemInstructionDisc)(
      (uint32_t)data[0] | ((uint32_t)data[1] << 8) |
      ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24));

  switch (tag) {
  // CreateAccount { lamports u64, space u64, owner pubkey }: [from, to].
  case CreateAccount: {
    const struct account_info *from;
    const struct account_info *to;
    uint64_t amount, from_balance;
    if (instruction->data.length < 52 || instruction->accounts.length < 2) {
      return cpi_program_failure("invalid CreateAccount data", CPI_BUILTIN(PROGRAM_ERROR_INVALID_INSTRUCTION_DATA));
    }
    if (!metas[0].is_signer || !metas[1].is_signer) {
      return cpi_program_failure("CreateAccount from and to must sign", CPI_BUILTIN(PROGRAM_ERROR_MISSING_REQUIRED_SIGNATURES));
    }
    from = cpi_find_account(account_infos, account_infos_len, metas[0].key);
    to = cpi_find_account(account_infos, account_infos_len, metas[1].key);
    if (from == NULL || to == NULL || from->lamports == NULL ||
        to->lamports == NULL || from->lamports->value == NULL ||
        to->lamports->value == NULL || to->owner == NULL) {
      klee_report_error(__FILE__, __LINE__,
                        "system CreateAccount account unavailable",
                        "cpi-runtime.err");
    }
    amount = token_load_u64(data + 4);
    from_balance = *from->lamports->value;
    if (amount > from_balance) {
      return cpi_program_failure("insufficient lamports for CreateAccount", CPI_CUSTOM(SYSTEM_RESULT_WITH_NEGATIVE_LAMPORTS));
    }
    *from->lamports->value = from_balance - amount;
    *to->lamports->value += amount;
    memcpy(to->owner, data + 20, sizeof(struct pubkey));
    return CPI_SUCCESS;
  }

  // Assign { owner: pubkey }: account [assigned].
  case Assign: {
    const struct account_info *account;
    if (instruction->data.length < 36 || instruction->accounts.length < 1) {
      return cpi_program_failure("invalid Assign data", CPI_BUILTIN(PROGRAM_ERROR_INVALID_INSTRUCTION_DATA));
    }
    if (!metas[0].is_signer) {
      return cpi_program_failure("Assign account must sign", CPI_BUILTIN(PROGRAM_ERROR_MISSING_REQUIRED_SIGNATURES));
    }
    account = cpi_find_account(account_infos, account_infos_len, metas[0].key);
    if (account == NULL || account->owner == NULL) {
      klee_report_error(__FILE__, __LINE__, "system Assign account unavailable",
                        "cpi-runtime.err");
    }
    memcpy(account->owner, data + 4, sizeof(struct pubkey));
    return CPI_SUCCESS;
  }

  // Transfer { lamports: u64 }: accounts [from, to].
  case Transfer: {
    const struct account_info *from;
    const struct account_info *to;
    uint64_t amount, from_balance, to_balance;
    if (instruction->data.length < 12 || instruction->accounts.length < 2) {
      return cpi_program_failure("invalid Transfer data", CPI_BUILTIN(PROGRAM_ERROR_INVALID_INSTRUCTION_DATA));
    }
    if (!metas[0].is_signer) {
      return cpi_program_failure("Transfer source must sign", CPI_BUILTIN(PROGRAM_ERROR_MISSING_REQUIRED_SIGNATURES));
    }
    if (!metas[0].is_writable || !metas[1].is_writable) {
      klee_report_error(__FILE__, __LINE__,
                        "system Transfer writes a readonly account",
                        "cpi-runtime.err");
    }
    from = cpi_find_account(account_infos, account_infos_len, metas[0].key);
    to = cpi_find_account(account_infos, account_infos_len, metas[1].key);
    if (from == NULL || to == NULL || from->lamports == NULL ||
        to->lamports == NULL || from->lamports->value == NULL ||
        to->lamports->value == NULL) {
      klee_report_error(__FILE__, __LINE__,
                        "system Transfer account unavailable", "cpi-runtime.err");
    }
    amount = token_load_u64(data + 4);
    from_balance = *from->lamports->value;
    if (amount > from_balance) {
      return cpi_program_failure("insufficient lamports for Transfer", CPI_CUSTOM(SYSTEM_RESULT_WITH_NEGATIVE_LAMPORTS));
    }
    if (from->lamports == to->lamports) {
      return CPI_SUCCESS;
    }
    to_balance = *to->lamports->value;
    if (UINT64_MAX - to_balance < amount) {
      return cpi_program_failure("lamport overflow", CPI_BUILTIN(PROGRAM_ERROR_INVALID_ARGUMENT));
    }
    *from->lamports->value = from_balance - amount;
    *to->lamports->value = to_balance + amount;
    return CPI_SUCCESS;
  }

  // Allocate { space: u64 }: account [allocated]. Agave requires the account
  // to sign, be empty, and be system-owned, bounds space, then set_data_length.
  // We don't grow the backing buffer -- the serialized account already reserves
  // MAX_PERMITTED_DATA_INCREASE of zeroed headroom -- but we do reflect the new
  // length so a later account.data_len() sees `space`, as it would after the CPI.
  case Allocate: {
    const struct account_info *account;
    uint64_t space;
    if (instruction->data.length < 12 || instruction->accounts.length < 1) {
      return cpi_program_failure("invalid Allocate data", CPI_BUILTIN(PROGRAM_ERROR_INVALID_INSTRUCTION_DATA));
    }
    if (!metas[0].is_signer) {
      return cpi_program_failure("Allocate account must sign", CPI_BUILTIN(PROGRAM_ERROR_MISSING_REQUIRED_SIGNATURES));
    }
    if (!metas[0].is_writable) {
      klee_report_error(__FILE__, __LINE__,
                        "system Allocate writes a readonly account",
                        "cpi-runtime.err");
    }
    account = cpi_find_account(account_infos, account_infos_len, metas[0].key);
    if (account == NULL || account->data == NULL || account->owner == NULL) {
      klee_report_error(__FILE__, __LINE__, "system Allocate account unavailable",
                        "cpi-runtime.err");
    }
    if (account->data->length != 0 ||
        !pubkeys_equal(account->owner, &SYSTEM_PROGRAM_ID)) {
      return cpi_program_failure("Allocate account already in use", CPI_CUSTOM(SYSTEM_ACCOUNT_ALREADY_IN_USE));
    }
    space = token_load_u64(data + 4);
    if (space > MAX_PERMITTED_DATA_LENGTH) {
      return cpi_program_failure("Allocate space exceeds maximum", CPI_CUSTOM(SYSTEM_INVALID_ACCOUNT_DATA_LENGTH));
    }
    account->data->length = space;
    return CPI_SUCCESS;
  }

  default:
    klee_report_error(__FILE__, __LINE__, "unmodeled system instruction",
                      "cpi.err");
    return CPI_SUCCESS;
  }
}
