// klee-session: run a linked bitcode module under KLEE, keep every terminated
// state's memory alive, and serve concrete reads of its symbolic address space
// over stdin until EOF. The process staying resident is what makes memory
// queryable after execution; closing stdin frees the states.
#include "klee/Core/Interpreter.h"
#include "klee/Expr/Constraints.h"
#include "klee/Expr/Expr.h"
#include "klee/Expr/ExprPPrinter.h"
#include "klee/Expr/ExprUtil.h"
#include "klee/Support/ErrorHandling.h"
#include "klee/Support/ModuleUtil.h"

// Internal KLEE headers (this tool builds inside the KLEE tree).
#include "AddressSpace.h"
#include "ExecutionState.h"
#include "Executor.h"
#include "Memory.h"

#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

using namespace klee;
using namespace llvm;

namespace {

// A kept copy of one terminated state's queryable memory and path condition.
struct Snapshot {
  AddressSpace addressSpace;
  ConstraintSet constraints;
  std::string suffix;
};

class SessionHandler : public InterpreterHandler {
  std::string dir;
  std::unique_ptr<llvm::raw_fd_ostream> info;

public:
  std::vector<Snapshot> snapshots;

  SessionHandler() {
    // KLEE writes run.stats/info into the output dir, so give it a real one.
    char tmpl[] = "/tmp/klee-session-XXXXXX";
    const char *made = mkdtemp(tmpl);
    dir = made ? made : "/tmp";
    std::error_code ec;
    info = std::make_unique<raw_fd_ostream>(dir + "/info", ec, sys::fs::OF_None);
  }
  llvm::raw_ostream &getInfoStream() const override { return *info; }
  std::string getOutputFilename(const std::string &f) override {
    return dir + "/" + f;
  }
  std::unique_ptr<llvm::raw_fd_ostream>
  openOutputFile(const std::string &f) override {
    std::error_code ec;
    return std::make_unique<raw_fd_ostream>(dir + "/" + f, ec,
                                            sys::fs::OF_None);
  }
  void incPathsCompleted() override {}
  void incPathsExplored(std::uint32_t = 1) override {}
  void processTestCase(const ExecutionState &state, const char *,
                       const char *suffix) override {
    snapshots.push_back(Snapshot{state.addressSpace, state.constraints,
                                 suffix ? std::string(suffix) : std::string()});
  }
};

} // namespace

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: klee-session LINKED.bc [RUNTIME_LIB_DIR] [OPT_SUFFIX]\n");
    return 2;
  }
  const std::string libDir = argc >= 3 ? argv[2] : "";
  // KLEE looks for libkleeRuntimeIntrinsic<OptSuffix>.bca in libDir.
  const std::string optSuffix = argc >= 4 ? argv[3] : "64_Release";

  // KLEE's external-call dispatcher JITs code, so the native target is needed.
  llvm::InitializeNativeTarget();
  llvm::InitializeNativeTargetAsmPrinter();
  llvm::InitializeNativeTargetAsmParser();

  LLVMContext ctx;
  std::vector<std::unique_ptr<Module>> modules;
  std::string err;
  if (!klee::loadFile(argv[1], ctx, modules, err)) {
    fprintf(stderr, "failed to load %s: %s\n", argv[1], err.c_str());
    return 2;
  }

  SessionHandler handler;
  Interpreter::InterpreterOptions iopts;
  std::unique_ptr<Interpreter> interp(Interpreter::create(ctx, iopts, &handler));
  Interpreter::ModuleOptions mopts(libDir, "main", optSuffix, false, false,
                                   false);
  llvm::Module *finalModule = interp->setModule(modules, mopts);
  Function *mainFn = finalModule->getFunction("main");
  if (!mainFn) {
    fprintf(stderr, "no main function in module\n");
    return 2;
  }

  char arg0[] = "klee-session";
  char *args[] = {arg0, nullptr};
  char *envp[] = {nullptr};
  interp->runFunctionAsMain(mainFn, 1, args, envp);

  Executor *exec = static_cast<Executor *>(interp.get());
  printf("ready snapshots=%zu\n", handler.snapshots.size());
  for (size_t i = 0; i < handler.snapshots.size(); ++i)
    printf("snapshot %zu %s\n", i, handler.snapshots[i].suffix.c_str());
  fflush(stdout);

  // Query loop: `read <idx> <hexaddr> <len>`, `count`, `quit`.
  std::string line;
  while (std::getline(std::cin, line)) {
    std::istringstream is(line);
    std::string cmd;
    is >> cmd;
    if (cmd == "quit")
      break;
    if (cmd == "count") {
      printf("%zu\n", handler.snapshots.size());
      fflush(stdout);
      continue;
    }
    if (cmd == "objects") {
      size_t idx = 0;
      if (!(is >> idx) || idx >= handler.snapshots.size()) {
        printf("error bad-args\n");
        fflush(stdout);
        continue;
      }
      const AddressSpace &as = handler.snapshots[idx].addressSpace;
      for (auto it = as.objects.begin(), e = as.objects.end(); it != e; ++it) {
        const MemoryObject *mo = it->first;
        printf("%llx %llu\n", (unsigned long long)mo->address,
               (unsigned long long)mo->size);
      }
      printf("end\n");
      fflush(stdout);
      continue;
    }
    if (cmd == "symbolic") {
      size_t idx = 0;
      unsigned long long addr = 0;
      unsigned len = 0;
      if (!(is >> idx >> std::hex >> addr >> std::dec >> len) ||
          idx >= handler.snapshots.size()) {
        printf("error bad-args\n");
        fflush(stdout);
        continue;
      }
      const AddressSpace &as = handler.snapshots[idx].addressSpace;
      std::string bits;
      std::vector<ref<Expr>> symExprs;
      bool ok = true;
      for (unsigned i = 0; i < len; ++i) {
        ref<klee::ConstantExpr> a =
            klee::ConstantExpr::create(addr + i, Context::get().getPointerWidth());
        ObjectPair op;
        if (!as.resolveOne(a, op)) {
          ok = false;
          break;
        }
        std::uint64_t off = (addr + i) - op.first->address;
        ref<Expr> byte = op.second->read(off, Expr::Int8);
        bool sym = byte->getKind() != Expr::Constant;
        bits.push_back(sym ? '1' : '0');
        if (sym)
          symExprs.push_back(byte);
      }
      if (!ok) {
        printf("unmapped\n");
        fflush(stdout);
        continue;
      }
      std::vector<const Array *> arrays;
      findSymbolicObjects(symExprs.begin(), symExprs.end(), arrays);
      printf("bits %s\n", bits.c_str());
      std::string names;
      for (const Array *arr : arrays) {
        if (!names.empty())
          names += " ";
        names += arr->getName();
      }
      printf("arrays %s\n", names.c_str());
      printf("end\n");
      fflush(stdout);
      continue;
    }
    if (cmd == "expr") {
      size_t idx = 0;
      unsigned long long addr = 0;
      unsigned len = 0;
      if (!(is >> idx >> std::hex >> addr >> std::dec >> len) ||
          idx >= handler.snapshots.size() || len == 0 || len > 8) {
        printf("error bad-args (len 1..8)\n");
        fflush(stdout);
        continue;
      }
      const AddressSpace &as = handler.snapshots[idx].addressSpace;
      ref<klee::ConstantExpr> a =
          klee::ConstantExpr::create(addr, Context::get().getPointerWidth());
      ObjectPair op;
      if (!as.resolveOne(a, op)) {
        printf("unmapped\n");
        fflush(stdout);
        continue;
      }
      std::uint64_t off = addr - op.first->address;
      ref<Expr> word = op.second->read(off, len * 8);
      std::string text;
      llvm::raw_string_ostream os(text);
      ExprPPrinter::printSingleExpr(os, word);
      os.flush();
      printf("exprbegin\n%s\nexprend\n", text.c_str());
      fflush(stdout);
      continue;
    }
    if (cmd == "read") {
      size_t idx = 0;
      unsigned long long addr = 0;
      unsigned len = 0;
      if (!(is >> idx >> std::hex >> addr >> std::dec >> len) ||
          idx >= handler.snapshots.size()) {
        printf("error bad-args\n");
        fflush(stdout);
        continue;
      }
      Snapshot &s = handler.snapshots[idx];
      std::vector<unsigned char> out;
      if (exec->readConcrete(s.addressSpace, s.constraints, addr, len, out)) {
        std::string hex;
        char buf[3];
        for (unsigned char b : out) {
          snprintf(buf, sizeof buf, "%02x", b);
          hex += buf;
        }
        printf("ok %s\n", hex.c_str());
      } else {
        printf("unmapped\n");
      }
      fflush(stdout);
      continue;
    }
    printf("error unknown-cmd\n");
    fflush(stdout);
  }
  return 0;
}
