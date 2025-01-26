# Find the Google Test package
find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

# Add test files
set(TEST_SOURCES
    test_FileDescriptor.cpp
    test_SocketGuard.cpp
    test_cmd_json.cpp
    test_atomic_write.cpp
)

# Create the test executable
add_executable(run_tests ${TEST_SOURCES})

# Link libraries
target_link_libraries(run_tests PRIVATE
    GTest::GTest
    GTest::Main
    ipmon_lib  # Link against the library instead of the executable
)

# Register the tests with CTest
add_test(NAME ipmon_tests COMMAND run_tests) 