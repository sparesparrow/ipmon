#include "ipmon.h"

int main(int argc, char* argv[]) {
    try {
        ipmon ipm;
        ipm.process_cmdline(argc, argv);
        ipm.start();
        auto listen_thread = std::thread(&ipmon::listen_socket, &ipm);
        listen_thread.detach();
        ipm.run();
    }
    catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
} 