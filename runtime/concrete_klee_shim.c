#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

void klee_make_symbolic(void *address, size_t size, const char *name) {
  (void)address;
  (void)size;
  (void)name;
}

void klee_assume(uintptr_t condition) { assert(condition); }

void klee_report_error(const char *file, int line, const char *message,
                       const char *suffix) {
  (void)file;
  (void)line;
  (void)message;
  (void)suffix;
  abort();
}
