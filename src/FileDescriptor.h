#include <unistd.h>

/*! RAII wrapper for file descriptors
 * This class is used to manage file descriptors.
 * It ensures that the file descriptor is closed when the object is destroyed.
 * It also provides move semantics to transfer ownership of the file descriptor.
 * 
 * Usage:
 * FileDescriptor fd(open("file", O_RDONLY));
 */
class FileDescriptor {
public:
    explicit FileDescriptor(int fd = -1) : _fd(fd) {}
    ~FileDescriptor() { if (_fd >= 0) close(_fd); }

    // Disable copy semantics
    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;

    // Enable move semantics
    FileDescriptor(FileDescriptor&& other) noexcept : _fd(other._fd) {
        other._fd = -1;
    }
    FileDescriptor& operator=(FileDescriptor&& other) noexcept {
        if (this != &other) {
            if (_fd >= 0) close(_fd);
            _fd = other._fd;
            other._fd = -1;
        }
        return *this;
    }

    int get() const { return _fd; }
    bool is_valid() const { return _fd >= 0; }

private:
    int _fd;
};
