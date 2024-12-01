#include <string>
#include <cstring>
#include <unistd.h>

/*! RAII wrapper for Unix domain sockets
 * This class is used to manage Unix domain sockets.
 * It ensures that the socket is closed when the object is destroyed.
 * It also provides move semantics to transfer ownership of the socket.
 * 
 * Usage:
 * SocketGuard sock(socket(AF_UNIX, SOCK_STREAM, 0), path);
 */
class SocketGuard {
public:
    SocketGuard(int sock, const std::string& path) : _sock(sock), _path(path) {}
    ~SocketGuard() {
        if (_sock >= 0) close(_sock);
        if (!_path.empty()) unlink(_path.c_str());
    }

    // Disable copy semantics
    SocketGuard(const SocketGuard&) = delete;
    SocketGuard& operator=(const SocketGuard&) = delete;

    // Enable move semantics
    SocketGuard(SocketGuard&& other) noexcept : _sock(other._sock), _path(other._path) {
        other._sock = -1;
        other._path.clear();
    }
    SocketGuard& operator=(SocketGuard&& other) noexcept {
        if (this != &other) {
            if (_sock >= 0) close(_sock);
            if (!_path.empty()) unlink(_path.c_str());
            _sock = other._sock;
            _path = other._path;
            other._sock = -1;
            other._path.clear();
        }
        return *this;
    }

    int get() const { return _sock; }

private:
    int _sock;
    std::string _path;
};
