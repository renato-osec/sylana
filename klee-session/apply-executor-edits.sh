#!/usr/bin/env bash
# Applied during the KLEE build (postPatch). Adds one public method to Executor
# that concretizes a byte range of a kept state's address space using the
# Executor's own solver. Kept as a script so it needs no nix-string escaping.
set -euo pipefail

# Declaration: a public method right at the top of the Executor class body.
sed -i \
  's#class Executor : public Interpreter {#class Executor : public Interpreter {\npublic:\n  bool readConcrete(const AddressSpace \&as, const ConstraintSet \&cs, std::uint64_t addr, unsigned len, std::vector<unsigned char> \&out);#' \
  lib/Core/Executor.h

# Definition: appended at file scope inside the klee namespace.
cat >> lib/Core/Executor.cpp <<'CPP'

namespace klee {
// Concretize `len` bytes at `addr` in a kept address space under `cs`.
bool Executor::readConcrete(const AddressSpace &as, const ConstraintSet &cs,
                            std::uint64_t addr, unsigned len,
                            std::vector<unsigned char> &out) {
  Expr::Width ptrWidth = Context::get().getPointerWidth();
  unsigned i = 0;
  while (i < len) {
    ref<ConstantExpr> a = ConstantExpr::create(addr + i, ptrWidth);
    ObjectPair op;
    if (!as.resolveOne(a, op))
      return false;
    std::uint64_t off = (addr + i) - op.first->address;
    // Read up to 8 bytes within this object as one expression, so the bytes of
    // a scalar are concretized jointly (consistent) rather than independently.
    unsigned chunk = len - i < 8 ? len - i : 8;
    if (off + chunk > op.first->size)
      chunk = static_cast<unsigned>(op.first->size - off);
    if (chunk == 0)
      return false;
    ref<Expr> word = op.second->read(off, chunk * 8);
    ref<ConstantExpr> val;
    SolverQueryMetaData md;
    if (!solver->getValue(cs, word, val, md))
      return false;
    std::uint64_t v = val->getZExtValue();
    for (unsigned b = 0; b < chunk; ++b)
      out.push_back(static_cast<unsigned char>((v >> (8 * b)) & 0xff));
    i += chunk;
  }
  return true;
}
} // namespace klee
CPP

echo "klee-session: Executor::readConcrete injected"
