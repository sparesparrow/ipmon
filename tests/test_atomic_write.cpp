#include <gtest/gtest.h>
#include "../src/ipmon.h"   // Include the header instead
#include <fstream>
#include <cstdio>

TEST(AtomicWriteTest, SuccessfulWrite)
{
    std::string path = "/tmp/test_atomic_write.txt";
    std::string content = "Hello, World!";
    auto result = atomic_write(path, content);
    EXPECT_FALSE(result.has_value());

    // Verify file contents
    std::ifstream ifs(path);
    ASSERT_TRUE(ifs.is_open());
    std::string file_content;
    std::getline(ifs, file_content);
    EXPECT_EQ(file_content, content);
    ifs.close();
    std::remove(path.c_str());
}

TEST(AtomicWriteTest, WriteToInvalidPath)
{
    std::string path = "/invalid_path/test_atomic_write.txt";
    std::string content = "Hello, World!";
    auto result = atomic_write(path, content);
    EXPECT_TRUE(result.has_value());
}

TEST(AtomicWriteTest, RenameFailure)
{
    // Attempt to write to a path where rename would fail
    // For example, writing to a directory instead of a file
    std::string path = "/tmp"; // Directory
    std::string content = "Should fail";
    auto result = atomic_write(path, content);
    EXPECT_TRUE(result.has_value());
} 