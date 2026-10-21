#ifndef OWNER_CHECK_PROCESS_INSTRUCTION_CALL_H
#define OWNER_CHECK_PROCESS_INSTRUCTION_CALL_H

#include <stddef.h>
#include <stdint.h>

// Rust sBPF ABI at the compiled process_instruction entry: final slice arg sits at the bottom of the caller's 4 KiB frame
// [r5 - 0x1000] = data pointer, [r5 - 0x0ff8] = data length
enum { PROCESS_INSTRUCTION_CALL_FRAME_LENGTH = 4096 };

struct process_instruction_call_frame {
  uint64_t data_address;
  uint64_t data_length;
  uint8_t reserved[PROCESS_INSTRUCTION_CALL_FRAME_LENGTH - 16];
};

_Static_assert(sizeof(struct process_instruction_call_frame) ==
                   PROCESS_INSTRUCTION_CALL_FRAME_LENGTH,
               "unexpected process_instruction caller frame size");
_Static_assert(offsetof(struct process_instruction_call_frame, data_address) ==
                   0,
               "unexpected process_instruction data pointer offset");
_Static_assert(offsetof(struct process_instruction_call_frame, data_length) ==
                   8,
               "unexpected process_instruction data length offset");

static inline void
prepare_process_instruction_call(uint64_t registers[10],
                                 struct process_instruction_call_frame *frame,
                                 const uint8_t *data, uint64_t data_length) {
  frame->data_address = (uint64_t)(uintptr_t)data;
  frame->data_length = data_length;
  registers[5] = (uint64_t)(uintptr_t)(frame + 1);
}

#endif
