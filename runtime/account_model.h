#ifndef OWNER_CHECK_ACCOUNT_MODEL_H
#define OWNER_CHECK_ACCOUNT_MODEL_H

#include <stddef.h>
#include <stdint.h>

struct pubkey {
  uint64_t words[4];
};

// RcBox<RefCell<&mut u64>> as used by this compiled Solana SDK
struct rc_refcell_u64 {
  uint64_t strong;
  uint64_t weak;
  uint64_t borrow;
  uint64_t *value;
};

// RcBox<RefCell<&mut [u8]>> as used by this compiled Solana SDK
struct rc_refcell_slice {
  uint64_t strong;
  uint64_t weak;
  uint64_t borrow;
  uint8_t *data;
  uint64_t length;
};

// Compiled #[repr(C)] Solana AccountInfo layout (48 bytes)
struct account_info {
  struct pubkey *key;              // +0
  struct rc_refcell_u64 *lamports; // +8
  struct rc_refcell_slice *data;   // +16
  struct pubkey *owner;            // +24
  uint64_t rent_epoch;             // +32
  uint8_t is_signer;               // +40
  uint8_t is_writable;             // +41
  uint8_t executable;              // +42
  uint8_t padding[5];              // +43
};

_Static_assert(sizeof(struct account_info) == 48, "unexpected AccountInfo ABI");
_Static_assert(offsetof(struct account_info, lamports) == 8,
               "unexpected AccountInfo.lamports offset");
_Static_assert(offsetof(struct account_info, data) == 16,
               "unexpected AccountInfo.data offset");
_Static_assert(offsetof(struct account_info, owner) == 24,
               "unexpected AccountInfo.owner offset");
_Static_assert(offsetof(struct rc_refcell_u64, borrow) == 16,
               "unexpected lamports RefCell borrow offset");
_Static_assert(offsetof(struct rc_refcell_u64, value) == 24,
               "unexpected lamports value offset");
_Static_assert(offsetof(struct rc_refcell_slice, data) == 24,
               "unexpected data pointer offset");
_Static_assert(offsetof(struct rc_refcell_slice, length) == 32,
               "unexpected data length offset");

static int pubkeys_equal(const struct pubkey *left,
                         const struct pubkey *right) {
  return left->words[0] == right->words[0] &&
         left->words[1] == right->words[1] &&
         left->words[2] == right->words[2] && left->words[3] == right->words[3];
}

#endif
