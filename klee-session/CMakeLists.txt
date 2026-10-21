# Builds the resident query tool inside the KLEE tree. It needs the internal
# Core headers (Executor.h, ExecutionState.h, AddressSpace.h, Memory.h), so
# lib/Core is added to the include path alongside the public KLEE includes.
add_executable(klee-session
  main.cpp
)

set(KLEE_LIBS
  kleeCore
)

target_link_libraries(klee-session ${KLEE_LIBS})
target_include_directories(klee-session PRIVATE
  ${KLEE_INCLUDE_DIRS}
  ${LLVM_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/lib/Core
)
target_compile_options(klee-session PRIVATE ${KLEE_COMPONENT_CXX_FLAGS})
target_compile_definitions(klee-session PRIVATE ${KLEE_COMPONENT_CXX_DEFINES})

install(TARGETS klee-session RUNTIME DESTINATION bin)

add_dependencies(klee-session BuildKLEERuntimes)
