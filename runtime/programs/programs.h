#ifndef SYLANA_PROGRAMS_H
#define SYLANA_PROGRAMS_H

#include <stdint.h>

#include "asset_model.h"

/*
 * The CPI layer: what sol_invoke_signed_rust (the invoke syscall) runs once its
 * arguments are translated. cpi_invoke() routes one instruction to the abstract
 * program that owns its program_id; each program is modeled in its own file
 * (system_program.c, token_program.c).
 *
 * A callee ProgramError is handed back to the caller as the u64 the SDK's
 * invoke() maps to Err(ProgramError), so the program's `?` propagates it and
 * the path ends as a failed transaction with the callee's error code (on
 * chain the VM is halted with that same error). Translation and privilege
 * violations are model boundaries and are reported to KLEE instead.
 */

enum { CPI_SUCCESS = 0 };
/* ProgramError encodings: builtin variants are `n << 32`, Custom(n) is n
 * (Custom(0) is 1 << 32). */
#define CPI_BUILTIN(n) ((uint64_t)(n) << 32)
#define CPI_CUSTOM(n) ((n) == 0 ? (UINT64_C(1) << 32) : (uint64_t)(n))
enum {
  PROGRAM_ERROR_INVALID_ARGUMENT = 2,
  PROGRAM_ERROR_INVALID_INSTRUCTION_DATA = 3,
  PROGRAM_ERROR_INVALID_ACCOUNT_DATA = 4,
  PROGRAM_ERROR_INCORRECT_PROGRAM_ID = 7,
  PROGRAM_ERROR_MISSING_REQUIRED_SIGNATURES = 8,
  PROGRAM_ERROR_NOT_ENOUGH_ACCOUNT_KEYS = 11,
};
/* SystemError and spl_token::TokenError discriminants (Custom errors). */
enum {
  SYSTEM_ACCOUNT_ALREADY_IN_USE = 0,
  SYSTEM_RESULT_WITH_NEGATIVE_LAMPORTS = 1,
  SYSTEM_INVALID_ACCOUNT_DATA_LENGTH = 3,
  TOKEN_INSUFFICIENT_FUNDS = 1,
  TOKEN_INVALID_MINT = 2,
  TOKEN_MINT_MISMATCH = 3,
  TOKEN_OWNER_MISMATCH = 4,
  TOKEN_FIXED_SUPPLY = 5,
  TOKEN_UNINITIALIZED_STATE = 9,
  TOKEN_OVERFLOW = 14,
  TOKEN_MINT_DECIMALS_MISMATCH = 18,
};

/* One CPI, already translated from the invoke syscall's r1..r5. */
uint64_t cpi_invoke(const struct stable_instruction *instruction,
                    const struct account_info *account_infos,
                    uint64_t account_infos_len, uint64_t signers_seeds_len);

/* Shared helpers for the abstract program models. `cpi_program_failure` logs
 * the reason and returns `error` (a CPI_BUILTIN/CPI_CUSTOM encoding). */
uint64_t cpi_program_failure(const char *message, uint64_t error);
const struct account_info *cpi_find_account(const struct account_info *infos,
                                            uint64_t infos_len,
                                            const uint8_t key[32]);

/* Abstract program: System (SOL transfers, account creation). */
uint64_t system_program_cpi(const struct stable_instruction *instruction,
                            const struct account_info *account_infos,
                            uint64_t account_infos_len);

/* Abstract program: SPL Token / Token-2022 (Transfer, TransferChecked). */
enum token_program_kind token_program_kind_for_id(const struct pubkey *program_id);
uint64_t token_program_cpi(const struct stable_instruction *instruction,
                           const struct account_info *account_infos,
                           uint64_t account_infos_len,
                           enum token_program_kind program_kind,
                           uint64_t signers_seeds_len);
/* Reset the token model's per-run counters (called from runtime init). */
void token_model_reset(void);

#endif
