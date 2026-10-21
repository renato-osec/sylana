#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#include <klee/klee.h>

extern uint64_t bpf_main(void *register_context, uint64_t context_size);

// Compiled Solana AccountInfo layout for this ELF (48 bytes).
struct account_info {
  uint8_t *key;        // +0
  void *lamports_rc;   // +8
  void *data_rc;       // +16
  uint8_t *owner;      // +24
  uint64_t rent_epoch; // +32
  uint64_t flags;      // +40
};

_Static_assert(sizeof(struct account_info) == 48, "unexpected AccountInfo ABI");
_Static_assert(offsetof(struct account_info, owner) == 24,
               "unexpected AccountInfo.owner offset");

// Rust's internal ProgramResult representation on this compiled path.
static const uint64_t INTERNAL_ILLEGAL_OWNER = UINT64_C(0x8000000000000011);

int main(void) {
  uint64_t registers[10] = {0};
  uint64_t result[3] = {0};
  uint8_t program_id[32] = {0};
  uint8_t vault_owner[32] = {0};
  uint8_t keys[3][32] = {{0}};
  struct account_info accounts[3] = {0};

  // Pointer topology is concrete.  Only the owner value is symbolic.
  program_id[0] = 0x42;
  klee_make_symbolic(vault_owner, sizeof(vault_owner), "vault_owner");
  klee_assume(vault_owner[0] != program_id[0]);

  // withdraw_safe reads record, treasury, recipient before the owner gate; the
  // mismatched record owner short-circuits to IllegalOwner.
  accounts[0].key = keys[0];
  accounts[0].owner = vault_owner;
  accounts[1].key = keys[1];
  accounts[2].key = keys[2];

  // withdraw_safe(result_out, program_id, accounts_ptr, accounts_len).
  registers[1] = (uint64_t)(uintptr_t)result;
  registers[2] = (uint64_t)(uintptr_t)program_id;
  registers[3] = (uint64_t)(uintptr_t)accounts;
  registers[4] = 3;

  (void)bpf_main(registers, sizeof(registers));
  klee_assert(result[0] == INTERNAL_ILLEGAL_OWNER);
  return 0;
}
