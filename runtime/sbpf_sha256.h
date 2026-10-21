#ifndef OWNER_CHECK_SBPF_SHA256_H
#define OWNER_CHECK_SBPF_SHA256_H

#include <stddef.h>
#include <stdint.h>

struct sbpf_sha256_context {
  uint32_t state[8];
  uint64_t bit_length;
  uint8_t block[64];
  size_t block_length;
};

void sbpf_sha256_init(struct sbpf_sha256_context *context);
void sbpf_sha256_update(struct sbpf_sha256_context *context,
                        const uint8_t *data, size_t length);
void sbpf_sha256_final(struct sbpf_sha256_context *context,
                       uint8_t output[32]);

#endif
