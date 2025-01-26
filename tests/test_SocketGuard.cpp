#include <gtest/gtest.h>
#include "../src/SocketGuard.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <cstdio>
#include <cstring>

TEST(SocketGuardTest, ValidSocket)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    ASSERT_NE(fd, -1);
    std::string path = "/tmp/test_socket_guard.sock";
    SocketGuard guard(fd, path);
    // The socket should be closed and the path unlinked when guard goes out of scope
    // Not directly testable here, but we can ensure no exceptions
}

TEST(SocketGuardTest, InvalidSocket)
{
    // Assuming negative file descriptor is invalid
    std::string path = "/tmp/test_socket_guard_invalid.sock";
    SocketGuard guard(-1, path);
    // Nothing happens
}

TEST(SocketGuardTest, MoveConstructor)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    ASSERT_NE(fd, -1);
    std::string path1 = "/tmp/test_socket_guard_move1.sock";
    std::string path2 = "/tmp/test_socket_guard_move2.sock";
    SocketGuard guard1(fd, path1);
    SocketGuard guard2(std::move(guard1));
    EXPECT_EQ(guard2.get(), fd);
    // guard1 should now have invalid state
}

TEST(SocketGuardTest, MoveAssignment)
{
    int fd1 = socket(AF_UNIX, SOCK_STREAM, 0);
    int fd2 = socket(AF_UNIX, SOCK_STREAM, 0);
    ASSERT_NE(fd1, -1);
    ASSERT_NE(fd2, -1);
    std::string path1 = "/tmp/test_socket_guard_move_assign1.sock";
    std::string path2 = "/tmp/test_socket_guard_move_assign2.sock";
    SocketGuard guard1(fd1, path1);
    SocketGuard guard2(fd2, path2);
    guard2 = std::move(guard1);
    EXPECT_EQ(guard2.get(), fd1);
    // guard1 should now have invalid state
} 