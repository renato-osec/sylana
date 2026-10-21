/*
 * The sBPF syscall layer: KLEE-side models for the imports emitted by
 * sbpf-normalize. Each _bpf_helper_ext_NNNN takes the live sBPF r1..r5 values
 * at the call site. The one non-trivial syscall, sol_invoke_signed_rust
 * (helper 5), hands its CPI off to the abstract-program models in programs/.
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <klee/klee.h>

#include "asset_model.h"
#include "programs/programs.h"
#include "sbpf_sha256.h"

static uint64_t sha256_calls;
static uint64_t log_format_summaries;
static uint64_t sylana_recorded_calls;
static uint64_t log_tail_length;
static struct sbpf_runtime_clock runtime_clock;
static struct sbpf_runtime_rent runtime_rent;
static const struct pubkey *pda_oracle_keys;
static uint64_t pda_oracle_key_count;

struct sol_bytes {
  const uint8_t *address;
  uint64_t length;
};

/* ---- Runtime state and lifecycle -------------------------------------- */

void sbpf_runtime_map_readonly(void *guest_address, const void *contents,
                               uint64_t length) {
  sbpf_runtime_map_readonly_regions(guest_address, contents, &length, 1);
}

void sbpf_runtime_map_readonly_regions(void *guest_address,
                                       const void *contents,
                                       const uint64_t *region_ends,
                                       uint64_t region_count) {
  uint8_t *const guest = (uint8_t *)guest_address;
  const uint8_t *const source = (const uint8_t *)contents;
  uint64_t region_start = 0;
  for (uint64_t region = 0; region < region_count; ++region) {
    const uint64_t region_end = region_ends[region];
    if (region_end <= region_start) {
      klee_report_error(__FILE__, __LINE__, "invalid read-only region layout",
                        "layout.err");
    }
    klee_define_fixed_object(guest + region_start, region_end - region_start);
    memcpy(guest + region_start, source + region_start,
           region_end - region_start);
    region_start = region_end;
  }
}

void sbpf_runtime_set_clock(const struct sbpf_runtime_clock *clock) {
  runtime_clock = *clock;
}

void sbpf_runtime_set_rent(const struct sbpf_runtime_rent *rent) {
  runtime_rent = *rent;
}

void pda_oracle_install(const struct pubkey *keys, uint64_t count) {
  if (count > 32) {
    klee_report_error(__FILE__, __LINE__, "PDA oracle is too large",
                      "oracle.err");
  }
  pda_oracle_keys = keys;
  pda_oracle_key_count = count;
}

/* The program's read-only image. The pipeline links a strong rodata.c for
 * whole-program runs; these weak defaults keep hand-written harnesses linking
 * (KLEE cannot resolve undefined weak declarations to null). */
const uint8_t *const sbpf_program_rodata __attribute__((weak)) = 0;
const uint64_t sbpf_program_rodata_vm_addr __attribute__((weak)) = 0;
const uint64_t *const sbpf_program_rodata_region_ends __attribute__((weak)) = 0;
const uint64_t sbpf_program_rodata_region_count __attribute__((weak)) = 0;

void sbpf_runtime_initialize(void) {
  if (sbpf_program_rodata_region_count) {
    sbpf_runtime_map_readonly_regions(
        (void *)(uintptr_t)sbpf_program_rodata_vm_addr, sbpf_program_rodata,
        sbpf_program_rodata_region_ends, sbpf_program_rodata_region_count);
  }
  void *const heap = (void *)(uintptr_t)UINT64_C(0x300000000);
  const size_t heap_length = 32 * 1024;
  klee_define_fixed_object(heap, heap_length);
  /* Solana's bump allocator only requires its cursor word to start at zero.
   * Vec writes initialize every allocated byte that this probe later reads. */
  *(uint64_t *)heap = 0;
  token_model_reset();
  sha256_calls = 0;
  log_format_summaries = 0;
  sylana_recorded_calls = 0;
  log_tail_length = 0;
  sbpf_log_tail[0] = 0;
  // Canonical sysvars: consistent values for sol_get_clock/rent_sysvar so a
  // program reading Clock::get()/Rent::get() sees sane, fixed state.
  runtime_clock.slot = SYLANA_CLOCK_SLOT;
  runtime_clock.epoch_start_timestamp = SYLANA_CLOCK_UNIX_TIMESTAMP;
  runtime_clock.epoch = SYLANA_CLOCK_EPOCH;
  runtime_clock.leader_schedule_epoch = SYLANA_CLOCK_EPOCH;
  runtime_clock.unix_timestamp = SYLANA_CLOCK_UNIX_TIMESTAMP;
  runtime_rent.lamports_per_byte_year = SYLANA_RENT_LAMPORTS_PER_BYTE_YEAR;
  runtime_rent.exemption_threshold = 2.0;
  runtime_rent.burn_percent = SYLANA_RENT_BURN_PERCENT;
}

uint64_t sbpf_runtime_sha256_calls(void) { return sha256_calls; }

int64_t sbpf_runtime_unix_timestamp(void) { return runtime_clock.unix_timestamp; }

uint64_t sbpf_runtime_log_format_summaries(void) {
  return log_format_summaries;
}

/* ---- Syscall table (imports emitted by sbpf-normalize) ---------------- */

/* Tail of the program's sol_log_ output: Anchor names the failing account and
 * constraint there, and a Rust panic logs its reason right before aborting. */
char sbpf_log_tail[SBPF_LOG_TAIL_BYTES];

static void log_tail_append(const char *text, uint64_t length) {
  const uint64_t room = sizeof(sbpf_log_tail) - 2; /* newline + NUL */
  /* A symbolic length would fork once per byte; keep concrete messages only. */
  if (klee_is_symbolic(length)) return;
  if (length > room) {
    text += length - room;
    length = room;
  }
  if (log_tail_length + length > room) {
    const uint64_t keep = room - length;
    memmove(sbpf_log_tail, sbpf_log_tail + log_tail_length - keep, keep);
    log_tail_length = keep;
  }
  for (uint64_t index = 0; index < length; ++index)
    sbpf_log_tail[log_tail_length + index] = text[index];
  log_tail_length += length;
  sbpf_log_tail[log_tail_length++] = '\n';
  sbpf_log_tail[log_tail_length] = 0;
}

void sbpf_runtime_log(const char *text) {
  uint64_t length = 0;
  while (text[length]) ++length;
  log_tail_append(text, length);
}

/* sol_log_ */
uint64_t _bpf_helper_ext_0001(uint64_t message, uint64_t length, uint64_t c,
                              uint64_t d, uint64_t e) {
  (void)c;
  (void)d;
  (void)e;
  log_tail_append((const char *)(uintptr_t)message, length);
  return 0;
}

/* abort */
uint64_t _bpf_helper_ext_0002(uint64_t a, uint64_t b, uint64_t c, uint64_t d,
                              uint64_t e) {
  (void)a;
  (void)b;
  (void)c;
  (void)d;
  (void)e;
  klee_report_error(__FILE__, __LINE__,
                    log_tail_length ? sbpf_log_tail : "sBPF abort", "abort.err");
}

/* sol_memset_ */
uint64_t _bpf_helper_ext_0003(uint64_t destination, uint64_t byte,
                              uint64_t length, uint64_t d, uint64_t e) {
  uint8_t *output = (uint8_t *)(uintptr_t)destination;
  (void)d;
  (void)e;
  for (uint64_t index = 0; index < length; ++index) {
    output[index] = (uint8_t)byte;
  }
  return destination;
}

/* sol_memcpy_ */
uint64_t _bpf_helper_ext_0004(uint64_t destination, uint64_t source,
                              uint64_t length, uint64_t d, uint64_t e) {
  uint8_t *output = (uint8_t *)(uintptr_t)destination;
  const uint8_t *input = (const uint8_t *)(uintptr_t)source;
  (void)d;
  (void)e;
  for (uint64_t index = 0; index < length; ++index) {
    output[index] = input[index];
  }
  return destination;
}

/* sol_invoke_signed_rust: translate the syscall's register arguments, then run
 * the CPI through the abstract-program layer (programs/). */
uint64_t _bpf_helper_ext_0005(uint64_t instruction_address,
                              uint64_t account_infos_address,
                              uint64_t account_infos_len,
                              uint64_t signers_seeds_address,
                              uint64_t signers_seeds_len) {
  const struct stable_instruction *instruction =
      (const struct stable_instruction *)(uintptr_t)instruction_address;
  const struct account_info *account_infos =
      (const struct account_info *)(uintptr_t)account_infos_address;
  (void)signers_seeds_address;
  return cpi_invoke(instruction, account_infos, account_infos_len,
                    signers_seeds_len);
}

/* sol_memcmp_ */
uint64_t _bpf_helper_ext_0006(uint64_t left_address, uint64_t right_address,
                              uint64_t length, uint64_t result_address,
                              uint64_t e) {
  const uint8_t *left = (const uint8_t *)(uintptr_t)left_address;
  const uint8_t *right = (const uint8_t *)(uintptr_t)right_address;
  int32_t *result = (int32_t *)(uintptr_t)result_address;
  int32_t difference = 0;
  (void)e;
  for (uint64_t index = 0; index < length; ++index) {
    if (difference == 0 && left[index] != right[index]) {
      difference = (int32_t)left[index] - (int32_t)right[index];
    }
  }
  *result = difference;
  return 0;
}

static int pda_oracle_contains(const uint8_t address[32]) {
  for (uint64_t index = 0; index < pda_oracle_key_count; ++index) {
    if (pubkey_bytes_equal(address, &pda_oracle_keys[index])) {
      return 1;
    }
  }
  return 0;
}

static int derive_program_address(const struct sol_bytes *seeds,
                                  uint64_t seed_count,
                                  const uint8_t program_id[32],
                                  const uint8_t *extra_seed,
                                  uint8_t output[32]) {
  static const uint8_t marker[] = "ProgramDerivedAddress";
  struct sbpf_sha256_context context;
  if (seed_count > 16) {
    return 0;
  }
  sbpf_sha256_init(&context);
  for (uint64_t index = 0; index < seed_count; ++index) {
    if (seeds[index].length > 32 ||
        (seeds[index].length != 0 && seeds[index].address == NULL)) {
      return 0;
    }
    sbpf_sha256_update(&context, seeds[index].address, seeds[index].length);
  }
  if (extra_seed != NULL) {
    sbpf_sha256_update(&context, extra_seed, 1);
  }
  sbpf_sha256_update(&context, program_id, 32);
  sbpf_sha256_update(&context, marker, sizeof(marker) - 1);
  sbpf_sha256_final(&context, output);

  /* For the frozen historical harness, membership in the concrete account
   * set is a stronger and cheaper oracle than symbolically checking whether
   * the compressed Ed25519 point is on curve. */
  return pda_oracle_contains(output);
}

/* sol_try_find_program_address */
uint64_t _bpf_helper_ext_0007(uint64_t seeds_address, uint64_t seeds_len,
                              uint64_t program_id_address,
                              uint64_t output_address,
                              uint64_t bump_address) {
  const struct sol_bytes *seeds =
      (const struct sol_bytes *)(uintptr_t)seeds_address;
  const uint8_t *program_id = (const uint8_t *)(uintptr_t)program_id_address;
  uint8_t *output = (uint8_t *)(uintptr_t)output_address;
  uint8_t *bump_output = (uint8_t *)(uintptr_t)bump_address;
  uint8_t derived[32];
  for (unsigned candidate = 256; candidate != 0; --candidate) {
    uint8_t bump = (uint8_t)(candidate - 1);
    if (derive_program_address(seeds, seeds_len, program_id, &bump, derived)) {
      for (unsigned index = 0; index < 32; ++index) output[index] = derived[index];
      *bump_output = bump;
      return 0;
    }
  }
  return 1;
}

/* sol_sha256 */
uint64_t _bpf_helper_ext_0008(uint64_t values_address, uint64_t values_len,
                              uint64_t output_address, uint64_t d,
                              uint64_t e) {
  const struct sol_bytes *values =
      (const struct sol_bytes *)(uintptr_t)values_address;
  uint8_t *output = (uint8_t *)(uintptr_t)output_address;
  struct sbpf_sha256_context context;
  (void)d;
  (void)e;
  if (values_len > 16) {
    klee_report_error(__FILE__, __LINE__, "SHA256 slice count exceeds model",
                      "model.err");
  }
  ++sha256_calls;
  sbpf_sha256_init(&context);
  for (uint64_t index = 0; index < values_len; ++index) {
    if (values[index].length > 1024 * 1024) {
      klee_report_error(__FILE__, __LINE__, "SHA256 input exceeds model",
                        "model.err");
    }
    sbpf_sha256_update(&context, values[index].address, values[index].length);
  }
  sbpf_sha256_final(&context, output);
  return 0;
}

/* sol_log_data */
uint64_t _bpf_helper_ext_0009(uint64_t fields_address, uint64_t fields_len,
                              uint64_t c, uint64_t d, uint64_t e) {
  (void)fields_address;
  (void)fields_len;
  (void)c;
  (void)d;
  (void)e;
  return 0;
}

/* sol_log_pubkey */
uint64_t _bpf_helper_ext_0010(uint64_t pubkey_address, uint64_t b, uint64_t c,
                              uint64_t d, uint64_t e) {
  (void)pubkey_address;
  (void)b;
  (void)c;
  (void)d;
  (void)e;
  return 0;
}

/* sol_create_program_address */
uint64_t _bpf_helper_ext_0011(uint64_t seeds_address, uint64_t seeds_len,
                              uint64_t program_id_address,
                              uint64_t output_address, uint64_t e) {
  const struct sol_bytes *seeds =
      (const struct sol_bytes *)(uintptr_t)seeds_address;
  const uint8_t *program_id = (const uint8_t *)(uintptr_t)program_id_address;
  uint8_t *output = (uint8_t *)(uintptr_t)output_address;
  uint8_t derived[32];
  (void)e;
  if (!derive_program_address(seeds, seeds_len, program_id, NULL, derived)) {
    return 1;
  }
  for (unsigned index = 0; index < 32; ++index) output[index] = derived[index];
  return 0;
}

/* sol_get_clock_sysvar */
uint64_t _bpf_helper_ext_0012(uint64_t output_address, uint64_t b, uint64_t c,
                              uint64_t d, uint64_t e) {
  uint8_t *output = (uint8_t *)(uintptr_t)output_address;
  const uint8_t *clock = (const uint8_t *)&runtime_clock;
  (void)b;
  (void)c;
  (void)d;
  (void)e;
  for (unsigned index = 0; index < sizeof(runtime_clock); ++index)
    output[index] = clock[index];
  return 0;
}

/* sol_get_rent_sysvar */
uint64_t _bpf_helper_ext_0013(uint64_t output_address, uint64_t b, uint64_t c,
                              uint64_t d, uint64_t e) {
  uint8_t *output = (uint8_t *)(uintptr_t)output_address;
  const uint8_t *rent = (const uint8_t *)&runtime_rent;
  (void)b;
  (void)c;
  (void)d;
  (void)e;
  for (unsigned index = 0; index < sizeof(runtime_rent); ++index)
    output[index] = rent[index];
  return 0;
}

/* sol_memmove_ */
uint64_t _bpf_helper_ext_0014(uint64_t destination, uint64_t source,
                              uint64_t length, uint64_t d, uint64_t e) {
  uint8_t *output = (uint8_t *)(uintptr_t)destination;
  const uint8_t *input = (const uint8_t *)(uintptr_t)source;
  (void)d;
  (void)e;
  if (output <= input || output >= input + length) {
    for (uint64_t index = 0; index < length; ++index) output[index] = input[index];
  } else {
    for (uint64_t index = length; index != 0; --index)
      output[index - 1] = input[index - 1];
  }
  return destination;
}

/* Optional normalizer summary for a Rust Vec<u8> producer whose result is
 * immediately consumed by sol_log_.  Current Solana Rust programs lay Vec out
 * as pointer/capacity/length.  An empty Vec avoids both formatter work and the
 * allocator/deallocator path, while preserving every non-log program value. */
uint64_t _bpf_helper_ext_0015(uint64_t output_address, uint64_t b, uint64_t c,
                              uint64_t d, uint64_t e) {
  uint64_t *const output = (uint64_t *)(uintptr_t)output_address;
  (void)b;
  (void)c;
  (void)d;
  (void)e;
  output[0] = 1; /* Non-null dangling pointer used by an empty Rust Vec. */
  output[1] = 0; /* capacity */
  output[2] = 0; /* length */
  ++log_format_summaries;
  return 0;
}

// Export one argument register as a named KLEE object carrying its value.
static void sylana_export_reg(const char *name, uint64_t value) {
  uint64_t out;
  klee_make_symbolic(&out, sizeof(out), name);
  klee_assume(out == value);
}

// Recorder for --record-calls-to: redirected calls land here so their
// argument registers r1..r5 are captured per path. The recorded function is
// not executed; continuation past the call is abandoned.
#define SYLANA_EXPORT_CALL(k)                                                  \
  do {                                                                         \
    sylana_export_reg("callarg." #k ".r1", r1);                               \
    sylana_export_reg("callarg." #k ".r2", r2);                               \
    sylana_export_reg("callarg." #k ".r3", r3);                               \
    sylana_export_reg("callarg." #k ".r4", r4);                               \
    sylana_export_reg("callarg." #k ".r5", r5);                               \
  } while (0)

uint64_t _bpf_helper_ext_0016(uint64_t r1, uint64_t r2, uint64_t r3,
                              uint64_t r4, uint64_t r5) {
  uint64_t index = sylana_recorded_calls++;
  switch (index) {
    case 0: SYLANA_EXPORT_CALL(0); break;
    case 1: SYLANA_EXPORT_CALL(1); break;
    case 2: SYLANA_EXPORT_CALL(2); break;
    case 3: SYLANA_EXPORT_CALL(3); break;
    case 4: SYLANA_EXPORT_CALL(4); break;
    case 5: SYLANA_EXPORT_CALL(5); break;
    case 6: SYLANA_EXPORT_CALL(6); break;
    case 7: SYLANA_EXPORT_CALL(7); break;
    default: break;
  }
  return 0;
}

uint64_t sbpf_runtime_recorded_calls(void) { return sylana_recorded_calls; }

/* sol_set_return_data / sol_get_return_data (Anchor v2 return values). A single
 * simulated top-level instruction, so a per-run buffer lets a program read back
 * what it wrote. ponytail: CPI callees don't populate this buffer, so a
 * get-after-CPI reads the last local set(); model the invoked program's return
 * data in the CPI layer if a transition ever depends on it. */
static uint8_t sbpf_return_data[1024];
static uint64_t sbpf_return_data_len = 0;

uint64_t _bpf_helper_ext_0017(uint64_t data_address, uint64_t length,
                              uint64_t c, uint64_t d, uint64_t e) {
  const uint8_t *input = (const uint8_t *)(uintptr_t)data_address;
  (void)c;
  (void)d;
  (void)e;
  if (length > sizeof(sbpf_return_data)) length = sizeof(sbpf_return_data);
  for (uint64_t index = 0; index < length; ++index)
    sbpf_return_data[index] = input[index];
  sbpf_return_data_len = length;
  return 0;
}

uint64_t _bpf_helper_ext_0018(uint64_t data_address, uint64_t length,
                              uint64_t program_id_address, uint64_t d,
                              uint64_t e) {
  uint8_t *output = (uint8_t *)(uintptr_t)data_address;
  const uint64_t available = sbpf_return_data_len;
  (void)d;
  (void)e;
  if (length > available) length = available;
  for (uint64_t index = 0; index < length; ++index)
    output[index] = sbpf_return_data[index];
  if (program_id_address) {
    uint8_t *program_id = (uint8_t *)(uintptr_t)program_id_address;
    for (unsigned index = 0; index < 32; ++index) program_id[index] = 0;
  }
  return available;
}

uint64_t sbpf_unresolved_callx(uint64_t target) {
  klee_print_expr("unresolved sBPF callx target", target);
  klee_report_error(__FILE__, __LINE__, "unresolved sBPF callx target",
                    "callx.err");
}

void sbpf_arithmetic_check(uint64_t invalid) {
  if (invalid) {
    klee_report_error(__FILE__, __LINE__,
                      "sBPF division by zero or signed division overflow",
                      "arithmetic.err");
  }
}
