#include <gtest/gtest.h>
#include "../src/FileDescriptor.h"
#include <fcntl.h>
#include <unistd.h>

TEST(FileDescriptorTest, ValidDescriptor)
{
    int fd = open("/dev/null", O_RDONLY);
    ASSERT_NE(fd, -1);
    FileDescriptor file_fd(fd);
    EXPECT_TRUE(file_fd.is_valid());
    EXPECT_EQ(file_fd.get(), fd);
}

TEST(FileDescriptorTest, InvalidDescriptor)
{
    FileDescriptor file_fd(-1);
    EXPECT_FALSE(file_fd.is_valid());
}

TEST(FileDescriptorTest, MoveConstructor)
{
    int fd = open("/dev/null", O_RDONLY);
    ASSERT_NE(fd, -1);
    FileDescriptor file_fd1(fd);
    FileDescriptor file_fd2(std::move(file_fd1));
    EXPECT_TRUE(file_fd2.is_valid());
    EXPECT_EQ(file_fd2.get(), fd);
    EXPECT_FALSE(file_fd1.is_valid());
}

TEST(FileDescriptorTest, MoveAssignment)
{
    int fd1 = open("/dev/null", O_RDONLY);
    int fd2 = open("/dev/null", O_RDONLY);
    ASSERT_NE(fd1, -1);
    ASSERT_NE(fd2, -1);
    FileDescriptor file_fd1(fd1);
    FileDescriptor file_fd2(fd2);
    file_fd2 = std::move(file_fd1);
    EXPECT_TRUE(file_fd2.is_valid());
    EXPECT_EQ(file_fd2.get(), fd1);
    EXPECT_FALSE(file_fd1.is_valid());
    // fd2 should now be closed when file_fd2 is overwritten
} 