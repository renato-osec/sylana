cmake_minimum_required(VERSION 3.20)
project(sbpf_llvm_emit LANGUAGES C CXX)

# Reserve Solana's 4096-byte max stack frame (V0 steps r10 by this fixed amount).
add_compile_definitions(EBPF_STACK_SIZE=4096)

include(FetchContent)
set(BUILD_LLVM_AOT_CLI OFF CACHE BOOL "" FORCE)
set(ENABLE_LLVM_SHARED YES CACHE BOOL "" FORCE)
FetchContent_Declare(
  llvmbpf
  GIT_REPOSITORY https://github.com/eunomia-bpf/llvmbpf.git
  GIT_TAG bd032ec921b8e4bec3a2ab0ff7507cfd83bedae3
  PATCH_COMMAND sh -c
                "git apply --reverse --check '${CMAKE_CURRENT_SOURCE_DIR}/llvmbpf-sbpf-stack.patch' >/dev/null 2>&1 || git apply --whitespace=nowarn '${CMAKE_CURRENT_SOURCE_DIR}/llvmbpf-sbpf-stack.patch'"
)
FetchContent_MakeAvailable(llvmbpf)

add_executable(sbpf-llvm-emit main.cpp)
target_compile_features(sbpf-llvm-emit PRIVATE cxx_std_20)
target_link_libraries(sbpf-llvm-emit PRIVATE llvmbpf_vm spdlog::spdlog)
