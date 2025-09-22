# Include necessary directories
include_directories(../../include)
include_directories(../../test/include)

# Create shared utils library from test code
add_library(shared_utils STATIC ../../test/core/shared_util.c)

# Build the fuzzing harness
add_executable(fuzz_harness src/fuzz_harness.c)
target_link_libraries(fuzz_harness LINK_PUBLIC shared_utils crypto pthread)

# Add fuzzing-specific compiler flags
target_compile_options(fuzz_harness PRIVATE -fsanitize=fuzzer -g)
target_link_options(fuzz_harness PRIVATE -fsanitize=fuzzer)

# Copy the executable to bin directory
add_custom_command(TARGET fuzz_harness POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:fuzz_harness> ${PROJECT_BINARY_DIR}/bin/fuzz_harness
        COMMAND ${CMAKE_COMMAND} -E remove $<TARGET_FILE:fuzz_harness>
        COMMENT "Created ${PROJECT_BINARY_DIR}/bin/fuzz_harness"
        )