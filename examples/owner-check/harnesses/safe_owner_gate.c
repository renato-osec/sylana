#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#include <klee/klee.h>

extern uint64_t bpf_main(void *register_context, uint64_t context_size);

struct pubkey {
  uint64_t words[4];
};

// Compiled Solana AccountInfo layout for this ELF (48 bytes).
struct account_info {
  struct pubkey *key;   // +0
  void *lamports_rc;    // +8
  void *data_rc;        // +16
  struct pubkey *owner; // +24
  uint64_t rent_epoch;  // +32
  uint64_t flags;       // +40
};

// Only +16 is needed on the deliberately-failing borrow path.
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
_Static_assert(offsetof(struct rc_refcell_slice, borrow) == 16,
               "unexpected RefCell borrow offset");

static const uint64_t INTERNAL_ACCOUNT_BORROW_FAILED =
    UINT64_C(0x800000000000000b);
static const uint64_t INTERNAL_ILLEGAL_OWNER = UINT64_C(0x8000000000000011);

static int pubkeys_equal(const struct pubkey *left,
                         const struct pubkey *right) {
  return left->words[0] == right->words[0] &&
         left->words[1] == right->words[1] &&
         left->words[2] == right->words[2] && left->words[3] == right->words[3];
}

int main(void) {
  uint64_t registers[10] = {0};
  uint64_t result[3] = {0};
  struct pubkey program_id = {{UINT64_C(0x42), 0, 0, 0}};
  struct pubkey vault_owner = {{0}};
  struct pubkey keys[3] = {{{0}}, {{0}}, {{0}}};
  struct rc_refcell_slice data_rc = {0};
  struct account_info accounts[3] = {0};

  // This exact 32-byte pointee is the symbolic AccountInfo.owner value.
  klee_make_symbolic(&vault_owner, sizeof(vault_owner), "vault_owner");

  // withdraw_safe reads record, treasury, recipient, then gates on both the
  // record and treasury owners. The treasury is program-owned, so the symbolic
  // record owner alone decides IllegalOwner vs reaching the failing borrow.
  data_rc.borrow = UINT64_MAX;
  accounts[0].key = &keys[0];
  accounts[0].data_rc = &data_rc;
  accounts[0].owner = &vault_owner;
  accounts[1].key = &keys[1];
  accounts[1].owner = &program_id;
  accounts[2].key = &keys[2];

  registers[1] = (uint64_t)(uintptr_t)result;
  registers[2] = (uint64_t)(uintptr_t)&program_id;
  registers[3] = (uint64_t)(uintptr_t)accounts;
  registers[4] = 3;

  (void)bpf_main(registers, sizeof(registers));

  if (pubkeys_equal(&vault_owner, &program_id)) {
    klee_assert(result[0] == INTERNAL_ACCOUNT_BORROW_FAILED);
  } else {
    klee_assert(result[0] == INTERNAL_ILLEGAL_OWNER);
  }
  return 0;
}
