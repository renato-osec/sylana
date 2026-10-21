/* CPI dispatch: translate-time validation shared by every program, then route
 * to the abstract program that owns the instruction's program_id. */
#include <stdint.h>

#include <klee/klee.h>

#include "programs/programs.h"

uint64_t cpi_program_failure(const char *message, uint64_t error) {
  char line[96] = "CPI failed: ";
  uint64_t at = 12;
  while (*message && at < sizeof(line) - 1) line[at++] = *message++;
  line[at] = 0;
  sbpf_runtime_log(line);
  return error;
}

const struct account_info *cpi_find_account(const struct account_info *infos,
                                            uint64_t infos_len,
                                            const uint8_t key[32]) {
  for (uint64_t index = 0; index < infos_len; ++index) {
    if (infos[index].key != NULL &&
        pubkey_bytes_equal(key, infos[index].key)) {
      return &infos[index];
    }
  }
  return NULL;
}

uint64_t cpi_invoke(const struct stable_instruction *instruction,
                    const struct account_info *account_infos,
                    uint64_t account_infos_len, uint64_t signers_seeds_len) {
  enum token_program_kind program_kind;

  /* Agave reports translation failures as syscall/VM errors, not as a value
   * returned to the caller. */
  if (instruction == NULL || account_infos == NULL) {
    klee_report_error(__FILE__, __LINE__, "invalid CPI syscall pointer",
                      "syscall.err");
  }
  if (account_infos_len > 32 || instruction->accounts.length > 8 ||
      instruction->data.length > 64) {
    klee_report_error(__FILE__, __LINE__, "CPI exceeds model bounds",
                      "model.err");
  }
  if ((instruction->accounts.length != 0 &&
       instruction->accounts.pointer == NULL) ||
      (instruction->data.length != 0 && instruction->data.pointer == NULL)) {
    klee_report_error(__FILE__, __LINE__, "invalid CPI vector pointer",
                      "syscall.err");
  }

  if (pubkeys_equal(&instruction->program_id, &SYSTEM_PROGRAM_ID)) {
    return system_program_cpi(instruction, account_infos, account_infos_len);
  }

  program_kind = token_program_kind_for_id(&instruction->program_id);
  if (program_kind == TOKEN_PROGRAM_NONE) {
    klee_report_error(__FILE__, __LINE__, "unmodeled CPI program", "cpi.err");
  }
  return token_program_cpi(instruction, account_infos, account_infos_len,
                           program_kind, signers_seeds_len);
}
