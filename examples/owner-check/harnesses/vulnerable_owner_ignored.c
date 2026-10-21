#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#include <klee/klee.h>

extern uint64_t bpf_main(void *register_context, uint64_t context_size);

struct pubkey {
  uint64_t words[4];
};

struct account_info {
  struct pubkey *key;
  void *lamports_rc;
  void *data_rc;
  struct pubkey *owner;
  uint64_t rent_epoch;
  uint64_t flags;
};

struct rc_refcell_slice {
  uint64_t strong;
  uint64_t weak;
  uint64_t borrow;
  uint8_t *data;
  uint64_t length;
};

_Static_assert(sizeof(struct account_info) == 48, "unexpected AccountInfo ABI");
_Static_assert(offsetof(struct account_info, data_rc) == 16,
               "unexpected AccountInfo.data offset");
_Static_assert(offsetof(struct account_info, owner) == 24,
               "unexpected AccountInfo.owner offset");

static const uint64_t INTERNAL_ACCOUNT_BORROW_FAILED =
    UINT64_C(0x800000000000000b);

int main(void) {
  uint64_t registers[10] = {0};
  uint64_t result[3] = {0};
  struct pubkey program_id = {{UINT64_C(0x42), 0, 0, 0}};
  struct pubkey vault_owner = {{0}};
  struct pubkey keys[3] = {{{0}}, {{0}}, {{0}}};
  struct rc_refcell_slice data_rc = {0};
  struct account_info accounts[3] = {0};

  klee_make_symbolic(&vault_owner, sizeof(vault_owner), "vault_owner");

  // withdraw_vulnerable reads record, treasury, recipient, then ignores the
  // record owner and borrows its data. The treasury must be program-owned so
  // the check passes and we reach try_borrow_data, which fails deterministically.
  data_rc.borrow = UINT64_MAX;
  accounts[0].key = &keys[0];
  accounts[0].data_rc = &data_rc;
  accounts[0].owner = &vault_owner;
  accounts[1].key = &keys[1];
  accounts[1].owner = &program_id;
  accounts[2].key = &keys[2];

  // withdraw_vulnerable(result_out, program_id, accounts_ptr, accounts_len): it
  // reads program_id for the treasury-owner check, so the arg is live.
  registers[1] = (uint64_t)(uintptr_t)result;
  registers[2] = (uint64_t)(uintptr_t)&program_id;
  registers[3] = (uint64_t)(uintptr_t)accounts;
  registers[4] = 3;

  (void)bpf_main(registers, sizeof(registers));
  klee_assert(result[0] == INTERNAL_ACCOUNT_BORROW_FAILED);
  return 0;
}
