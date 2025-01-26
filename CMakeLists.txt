# CMakeLists.txt

cmake_minimum_required(VERSION 3.12)
project(ipmon VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# Add compiler warnings
add_compile_options(
    -Wall 
    -Werror 
    -Wextra 
    -Wno-c++98-compat 
    -Wno-c++98-compat-pedantic
    -Wno-system-headers 
    -Wno-padded 
    -Wno-undefined-var-template 
    -Wunreachable-code
)

# Find required packages
find_package(PkgConfig REQUIRED)
pkg_check_modules(JSONCPP REQUIRED jsoncpp)
pkg_check_modules(NFTABLES REQUIRED libnftables)

# Source files
set(SOURCES
    src/ipmon.cpp
    # TODO: consider splitting into separate source files
    # src/network/interface_monitor.cpp
    # src/network/address_manager.cpp
    # src/config/nft_manager.cpp
    # src/config/proxy_manager.cpp
    # src/utils/json_builder.cpp
    # src/utils/file_utils.cpp
    # src/utils/socket_utils.cpp
)

# Create a library from the source files
add_library(ipmon_lib STATIC ${SOURCES})

# Set include directories for the library
target_include_directories(ipmon_lib PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${JSONCPP_INCLUDE_DIRS}
    ${NFTABLES_INCLUDE_DIRS}
)

# Link libraries to ipmon_lib
target_link_libraries(ipmon_lib PUBLIC
    ${JSONCPP_LIBRARIES}
    ${NFTABLES_LIBRARIES}
    pthread
)

# Add executable
add_executable(ipmon src/main.cpp)

# Link the executable with our library
target_link_libraries(ipmon PRIVATE ipmon_lib)

# Installation rules
install(TARGETS ipmon
    RUNTIME DESTINATION bin
)

install(TARGETS ipmon_lib
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

# Install service file
install(FILES systemd/ipmon.service
    DESTINATION /lib/systemd/system/
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
)

# Install configuration directory
install(DIRECTORY DESTINATION /etc/impon)
install(DIRECTORY DESTINATION /etc/ipmon)

# Set up runtime directory
install(DIRECTORY DESTINATION /run/ipmon
    DIRECTORY_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE 
                         GROUP_READ GROUP_EXECUTE 
                         WORLD_READ WORLD_EXECUTE
)

# Add testing
enable_testing()
add_subdirectory(tests)

# Package version and maintainer info
set(CPACK_PACKAGE_VERSION "0.0.1")
set(CPACK_PACKAGE_CONTACT "sparesparrow <sparesparrow@protonmail.ch>")

# Debian package specific configurations
set(CPACK_GENERATOR "DEB")

# Read and parse package description file
file(READ "${CMAKE_SOURCE_DIR}/pkg-files/package-description.txt" PACKAGE_DESCRIPTION_CONTENT)

# Extract fields from package description file
string(REGEX REPLACE ".*Section: ([^\n]*)\n.*" "\\1" CPACK_DEBIAN_PACKAGE_SECTION "${PACKAGE_DESCRIPTION_CONTENT}")
string(REGEX REPLACE ".*Priority: ([^\n]*)\n.*" "\\1" CPACK_DEBIAN_PACKAGE_PRIORITY "${PACKAGE_DESCRIPTION_CONTENT}")
string(REGEX REPLACE ".*Depends: ([^\n]*)\n.*" "\\1" CPACK_DEBIAN_PACKAGE_DEPENDS "${PACKAGE_DESCRIPTION_CONTENT}")
string(REGEX REPLACE ".*Description: ([^\n]*)\n.*" "\\1" CPACK_PACKAGE_DESCRIPTION_SUMMARY "${PACKAGE_DESCRIPTION_CONTENT}")
string(REGEX REPLACE ".*Description:[^\n]*\n(.*)" "\\1" CPACK_PACKAGE_DESCRIPTION "${PACKAGE_DESCRIPTION_CONTENT}")

# Install scripts
set(CPACK_DEBIAN_PACKAGE_CONTROL_STRICT_PERMISSION TRUE)
set(CPACK_DEBIAN_PACKAGE_MAINTAINER_SCRIPTS_DIR "${CMAKE_SOURCE_DIR}/pkg-files")
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA
    "${CMAKE_SOURCE_DIR}/pkg-files/preinst"
    "${CMAKE_SOURCE_DIR}/pkg-files/postinst"
    "${CMAKE_SOURCE_DIR}/pkg-files/prerm"
    "${CMAKE_SOURCE_DIR}/pkg-files/postrm"
)

# Install systemd service file
install(FILES "${CMAKE_SOURCE_DIR}/systemd/ipmon.service"
        DESTINATION "/lib/systemd/system"
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

# Create required directories
install(DIRECTORY DESTINATION "/etc/ipmon"
        DIRECTORY_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
                            GROUP_READ GROUP_EXECUTE
                            WORLD_READ WORLD_EXECUTE)

install(DIRECTORY DESTINATION "/run/ipmon"
        DIRECTORY_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
                            GROUP_READ GROUP_EXECUTE
                            WORLD_READ WORLD_EXECUTE)

# Make sure this comes last
include(CPack)