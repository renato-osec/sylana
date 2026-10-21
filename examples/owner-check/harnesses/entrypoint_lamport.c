#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <klee/klee.h>

#include "asset_model.h"

#ifndef ENTRYPOINT_SELECTOR
#error "ENTRYPOINT_SELECTOR must select the test instruction"
#endif

extern uint64_t bpf_main(void *register_context, uint64_t context_size);

enum {
  ENTRYPOINT_INPUT_LENGTH = 40 * 1024,
  MAX_PERMITTED_DATA_INCREASE = 10 * 1024,
};

static void write_u64(uint8_t *output, uint64_t value) {
  memcpy(output, &value, sizeof(value));
}

static uint64_t read_u64(const uint8_t *input) {
  uint64_t value;
  memcpy(&value, input, sizeof(value));
  return value;
}

static size_t append_account(uint8_t *input, size_t offset,
                             const struct pubkey *key,
                             const struct pubkey *owner, uint64_t lamports,
                             const uint8_t *data, uint64_t data_length,
                             uint8_t is_writable, size_t *lamports_offset) {
  input[offset++] = UINT8_MAX; // NON_DUP_MARKER
  input[offset++] = 0;         // is_signer
  input[offset++] = is_writable;
  input[offset++] = 0;        // executable
  offset += sizeof(uint32_t); // original data length, set by deserializer
  memcpy(input + offset, key, sizeof(*key));
  offset += sizeof(*key);
  memcpy(input + offset, owner, sizeof(*owner));
  offset += sizeof(*owner);
  *lamports_offset = offset;
  write_u64(input + offset, lamports);
  offset += sizeof(uint64_t);
  write_u64(input + offset, data_length);
  offset += sizeof(uint64_t);
  if (data_length != 0) {
    memcpy(input + offset, data, data_length);
  }
  offset += data_length + MAX_PERMITTED_DATA_INCREASE;
  offset = (offset + 7) & ~(size_t)7;    // BPF_ALIGN_OF_U128
  write_u64(input + offset, UINT64_MAX); // rent_epoch
  return offset + sizeof(uint64_t);
}

int main(void) {
  uint64_t registers[10] = {0};
  _Alignas(8) uint8_t input[ENTRYPOINT_INPUT_LENGTH];
  struct pubkey program_id = {{UINT64_C(0x42), 0, 0, 0}};
  struct pubkey record_owner = {{0}};
  struct pubkey recipient_owner = {{UINT64_C(0x99), 0, 0, 0}};
  struct pubkey keys[3] = {{{1, 0, 0, 0}}, {{2, 0, 0, 0}}, {{3, 0, 0, 0}}};
  uint64_t requested_amount;
  uint8_t record_data[8];
  size_t record_lamports_offset;
  size_t treasury_lamports_offset;
  size_t recipient_lamports_offset;
  size_t offset = 0;

  klee_make_symbolic(&record_owner, sizeof(record_owner), "record.owner");
  klee_make_symbolic(&requested_amount, sizeof(requested_amount),
                     "record.data.amount");
#ifndef EXPECT_SAFE_TRANSFER
  klee_assume(record_owner.words[0] != program_id.words[0]);
#endif
  // Byte-store loop, not memcpy: memcpy is an external call KLEE concretizes,
  // which would collapse the symbolic amount to a single value.
  for (unsigned j = 0; j < sizeof(record_data); ++j)
    record_data[j] = ((const uint8_t *)&requested_amount)[j];

  write_u64(input + offset, 3);
  offset += sizeof(uint64_t);
  offset =
      append_account(input, offset, &keys[0], &record_owner, 1, record_data,
                     sizeof(record_data), 0, &record_lamports_offset);
  offset = append_account(input, offset, &keys[1], &program_id, 100, NULL, 0, 1,
                          &treasury_lamports_offset);
  offset = append_account(input, offset, &keys[2], &recipient_owner, 10, NULL,
                          0, 1, &recipient_lamports_offset);
  write_u64(input + offset, 1);
  offset += sizeof(uint64_t);
  input[offset++] = ENTRYPOINT_SELECTOR;
  memcpy(input + offset, &program_id, sizeof(program_id));
  offset += sizeof(program_id);
  klee_assert(offset <= sizeof(input));

  const uint64_t treasury_before = read_u64(input + treasury_lamports_offset);
  const uint64_t recipient_before = read_u64(input + recipient_lamports_offset);

  sbpf_runtime_initialize();
  (void)registers;
  // Whole-program lift: bpf_main's first arg IS r1 (the input pointer).
  const uint64_t status = bpf_main((void *)(uintptr_t)input, sizeof(input));

  if (status == 0 &&
      asset_transfer_observed(
          treasury_before, read_u64(input + treasury_lamports_offset),
          recipient_before, read_u64(input + recipient_lamports_offset))) {
#ifdef EXPECT_SAFE_TRANSFER
    klee_assert(pubkeys_equal(&record_owner, &program_id));
    klee_report_error(__FILE__, __LINE__, "entrypoint lamports transferred",
                      "entrypoint-transfer.err");
#else
    klee_assert(!pubkeys_equal(&record_owner, &program_id));
    klee_report_error(__FILE__, __LINE__,
                      "entrypoint transfer from an unowned record",
                      "entrypoint-unauthorized-transfer.err");
#endif
  }
  (void)record_lamports_offset;
  return 0;
}
