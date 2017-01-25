CMAKE_MINIMUM_REQUIRED(VERSION 2.8.1)
PROJECT(libtins)

# Compile in release mode by default
IF(NOT CMAKE_BUILD_TYPE)
    MESSAGE(STATUS "Setting build type to 'RelWithDebInfo' as none was specified.")
    SET(CMAKE_BUILD_TYPE RelWithDebInfo)
ELSE(NOT CMAKE_BUILD_TYPE)
    MESSAGE(STATUS "Using specified '${CMAKE_BUILD_TYPE}' build type.")
ENDIF(NOT CMAKE_BUILD_TYPE)

# Compilation flags.
IF(MSVC)
    # Don't always use Wall, since VC's /Wall is ridiculously verbose.
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W3")
    # Disable VC secure checks, since these are not really issues.
    ADD_DEFINITIONS("-D_CRT_SECURE_NO_WARNINGS=1")
    ADD_DEFINITIONS("-D_SCL_SECURE_NO_WARNINGS=1")
    ADD_DEFINITIONS("-DNOGDI=1")
ELSE()
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")
ENDIF()

IF(APPLE)
    # This is set to ON as of policy CMP0042
    SET(CMAKE_MACOSX_RPATH ON)
ENDIF()

# Build output checks
OPTION(LIBTINS_BUILD_SHARED "Build libtins as a shared library." ON)
IF(LIBTINS_BUILD_SHARED)
    MESSAGE(
        STATUS
        "Build will generate a shared library. "
        "Use LIBTINS_BUILD_SHARED=0 to perform a static build"
    )
    SET(LIBTINS_TYPE SHARED)
ELSE(LIBTINS_BUILD_SHARED)
    MESSAGE(STATUS "Build will generate a static library.")
    SET(LIBTINS_TYPE STATIC)
    ADD_DEFINITIONS("-DTINS_STATIC=1")
ENDIF(LIBTINS_BUILD_SHARED)

# The version number.
SET(LIBTINS_VERSION_MAJOR 3)
SET(LIBTINS_VERSION_MINOR 4)
SET(LIBTINS_VERSION "${LIBTINS_VERSION_MAJOR}.${LIBTINS_VERSION_MINOR}")

# Required Packages
SET(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules/")

# Look for libpcap
FIND_PACKAGE(PCAP REQUIRED)

# Set some Windows specific flags
IF(WIN32)
    # We need to link against these libs
    SET(LIBTINS_OS_LIBS Ws2_32.lib Iphlpapi.lib)

    # Add the NOMINMAX macro to avoid Windows' min and max macros.
    ADD_DEFINITIONS(-DNOMINMAX)

    # MinWG need some extra definitions to compile properly (WIN32 for PCAP and WIN32_WINNT version for ws2tcpip.h)
    IF(MINGW)
        ADD_DEFINITIONS(-DWIN32)
        MACRO(get_WIN32_WINNT version)
        IF (WIN32 AND CMAKE_SYSTEM_VERSION)
            SET(ver ${CMAKE_SYSTEM_VERSION})
            STRING(REPLACE "." "" ver ${ver})
            STRING(REGEX REPLACE "([0-9])" "0\\1" ver ${ver})
            SET(${version} "0x${ver}")
        ENDIF()
        ENDMACRO()
        get_WIN32_WINNT(ver)
        ADD_DEFINITIONS(-D_WIN32_WINNT=${ver})
    ENDIF(MINGW)

ENDIF(WIN32)

INCLUDE(ExternalProject)

# *******************
# Compilation options
# *******************

# Always check for C++ features
INCLUDE(CheckCXXFeatures)

IF(HAS_GCC_BUILTIN_SWAP)
    SET(TINS_HAVE_GCC_BUILTIN_SWAP ON)
ENDIF()

# C++11 support
OPTION(LIBTINS_ENABLE_CXX11 "Compile libtins with c++11 features" ON)
IF(LIBTINS_ENABLE_CXX11)
    # We only use declval and decltype on gcc/clang as VC fails to build that code,
    # at least on VC2013
    IF(HAS_CXX11_RVALUE_REFERENCES AND HAS_CXX11_FUNCTIONAL AND HAS_CXX11_CHRONO AND
       HAS_CXX11_NOEXCEPT AND ((HAS_CXX11_DECLVAL AND HAS_CXX11_DECLTYPE) OR MSVC))
        SET(TINS_HAVE_CXX11 ON)
        MESSAGE(STATUS "Enabling C++11 features")
        SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CXX11_COMPILER_FLAGS}")
    ELSE()
        MESSAGE(WARNING "The compiler doesn't support the necessary C++11 features. "
                        "Disabling C++11 on this build")
    ENDIF()
ELSE(LIBTINS_ENABLE_CXX11)
    MESSAGE(
        WARNING
        "Disabling C++11 features. Use LIBTINS_ENABLE_CXX11=1 to enable them. "
        "Unless you are using an old compiler, you should enable this option, "
        "as it increases the library's performance")
ENDIF(LIBTINS_ENABLE_CXX11)

# IEEE 802.11 and WPA2 decryption support
OPTION(LIBTINS_ENABLE_DOT11 "Compile libtins with IEEE 802.11 support" ON)
OPTION(LIBTINS_ENABLE_WPA2 "Compile libtins with WPA2 decryption features (requires OpenSSL)" ON)
IF(LIBTINS_ENABLE_DOT11)
    SET(TINS_HAVE_DOT11 ON)
    MESSAGE(STATUS "Enabling IEEE 802.11 support.")
    IF(LIBTINS_ENABLE_WPA2)
        FIND_PACKAGE(OpenSSL)
        IF(OPENSSL_FOUND)
            SET(TINS_HAVE_WPA2_DECRYPTION ON)
            MESSAGE(STATUS "Enabling WPA2 decryption support.")
        ELSE()
            MESSAGE(WARNING "Disabling WPA2 decryption support since OpenSSL was not found")
            # Default this to empty strings
            SET(OPENSSL_INCLUDE_DIR "")
            SET(OPENSSL_LIBRARIES "")
        ENDIF()
    ELSE(LIBTINS_ENABLE_WPA2)
        MESSAGE(STATUS "Disabling WPA2 decryption support.")
    ENDIF(LIBTINS_ENABLE_WPA2)
ENDIF(LIBTINS_ENABLE_DOT11)

# Optionally enable TCPIP classes (on by default)
OPTION(LIBTINS_ENABLE_TCPIP "Enable TCPIP classes" ON)
IF(LIBTINS_ENABLE_TCPIP AND TINS_HAVE_CXX11)
    SET(TINS_HAVE_TCPIP ON)
    MESSAGE(STATUS "Enabling TCPIP classes")
ELSE()
    SET(TINS_HAVE_TCPIP OFF)
    MESSAGE(STATUS "Disabling TCPIP classes")
ENDIF()

# Search for libboost
FIND_PACKAGE(Boost)

# Optionally enable the ACK tracker (on by default)
OPTION(LIBTINS_ENABLE_ACK_TRACKER "Enable TCP ACK tracking support" ON)
IF(LIBTINS_ENABLE_ACK_TRACKER AND TINS_HAVE_CXX11)
    IF (Boost_FOUND)
        MESSAGE(STATUS "Enabling TCP ACK tracking support.")
        INCLUDE_DIRECTORIES(${Boost_INCLUDE_DIRS})
        SET(TINS_HAVE_ACK_TRACKER ON)
    ELSE()
        MESSAGE(WARNING "Disabling ACK tracking support as boost.icl was not found")
        SET(TINS_HAVE_ACK_TRACKER OFF)
    ENDIF()
ELSE()
    SET(TINS_HAVE_ACK_TRACKER OFF)
    MESSAGE(STATUS "Disabling ACK tracking support")
ENDIF()

# Optionally enable the TCP stream custom data (on by default)
OPTION(LIBTINS_ENABLE_TCP_STREAM_CUSTOM_DATA "Enable TCP stream custom data support" ON)
IF(LIBTINS_ENABLE_TCP_STREAM_CUSTOM_DATA AND TINS_HAVE_CXX11)
    IF (Boost_FOUND)
        MESSAGE(STATUS "Enabling TCP stream custom data support.")
        INCLUDE_DIRECTORIES(${Boost_INCLUDE_DIRS})
        SET(TINS_HAVE_TCP_STREAM_CUSTOM_DATA ON)
    ELSE()
        MESSAGE(WARNING "Disabling TCP stream custom data support as boost.any was not found")
        SET(TINS_HAVE_TCP_STREAM_CUSTOM_DATA OFF)
    ENDIF()
ELSE()
    SET(TINS_HAVE_TCP_STREAM_CUSTOM_DATA OFF)
    MESSAGE(STATUS "Disabling TCP stream custom data support")
ENDIF()

OPTION(LIBTINS_ENABLE_WPA2_CALLBACKS "Enable WPA2 callback interface" ON)
IF(LIBTINS_ENABLE_WPA2_CALLBACKS AND TINS_HAVE_WPA2_DECRYPTION AND TINS_HAVE_CXX11)
    SET(STATUS "Enabling WPA2 callback interface")
    SET(TINS_HAVE_WPA2_CALLBACKS ON)
ENDIF()

# Use pcap_sendpacket to send l2 packets rather than raw sockets
IF(WIN32)
    SET(USE_PCAP_SENDPACKET_DEFAULT ON)
ELSE(WIN32)
    SET(USE_PCAP_SENDPACKET_DEFAULT OFF)
ENDIF(WIN32)

OPTION(LIBTINS_USE_PCAP_SENDPACKET "Use pcap_sendpacket to send l2 packets"
        ${USE_PCAP_SENDPACKET_DEFAULT})
IF(LIBTINS_USE_PCAP_SENDPACKET)
    SET(TINS_HAVE_PACKET_SENDER_PCAP_SENDPACKET ON)
    MESSAGE(STATUS "Using pcap_sendpacket to send l2 packets.")
ENDIF(LIBTINS_USE_PCAP_SENDPACKET)

# Add a target to generate API documentation using Doxygen
FIND_PACKAGE(Doxygen QUIET)
IF(DOXYGEN_FOUND)
    CONFIGURE_FILE(
        ${CMAKE_CURRENT_SOURCE_DIR}/docs/Doxyfile.in
        ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
        @ONLY
    )
    ADD_CUSTOM_TARGET(
        docs
        ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Generating API documentation with Doxygen" VERBATIM
    )
ENDIF(DOXYGEN_FOUND)

# The library output directory
SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
SET(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)

# Configuration file
CONFIGURE_FILE(
  "${PROJECT_SOURCE_DIR}/include/tins/config.h.in"
  "${PROJECT_SOURCE_DIR}/include/tins/config.h"
)

# Support for pkg-config
SET(CMAKE_INSTALL_LIBDIR lib)
SET(pkgconfig_prefix      ${CMAKE_INSTALL_PREFIX})
SET(pkgconfig_exec_prefix ${CMAKE_INSTALL_PREFIX})
SET(pkgconfig_libdir      ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR})
SET(pkgconfig_version     ${LIBTINS_VERSION})
CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/libtins.pc.in
                ${CMAKE_CURRENT_BINARY_DIR}/libtins.pc @ONLY)

INSTALL(
    FILES
    ${CMAKE_CURRENT_BINARY_DIR}/libtins.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)

# Confiugure the uninstall script
CONFIGURE_FILE(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/cmake_uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY
)

# Add uninstall target
ADD_CUSTOM_TARGET(uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)

# ******************
# Add subdirectories
# ******************
ADD_SUBDIRECTORY(include)
ADD_SUBDIRECTORY(examples)
ADD_SUBDIRECTORY(src)

# Only include googletest if the git submodule has been fetched
IF(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/googletest/CMakeLists.txt")
    # Enable tests and add the test directory
    MESSAGE(STATUS "Tests have been enabled")
    SET(GOOGLETEST_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/googletest)
    SET(GOOGLETEST_INCLUDE ${GOOGLETEST_ROOT}/googletest/include)
    SET(GOOGLETEST_BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/googletest)
    SET(GOOGLETEST_LIBRARY ${GOOGLETEST_BINARY_DIR}/googletest)

    ExternalProject_Add(
        googletest
        DOWNLOAD_COMMAND ""
        SOURCE_DIR ${GOOGLETEST_ROOT}
        BINARY_DIR ${GOOGLETEST_BINARY_DIR}
        CMAKE_CACHE_ARGS "-DBUILD_GTEST:bool=ON" "-DBUILD_GMOCK:bool=OFF"
                         "-Dgtest_force_shared_crt:bool=ON"
        INSTALL_COMMAND ""
    )
    # Make sure we build googletest before anything else
    ADD_DEPENDENCIES(tins googletest)
    ENABLE_TESTING()
    ADD_SUBDIRECTORY(tests)
ELSE()
    MESSAGE(STATUS "googletest git submodule is absent. Run `git submodule init && git submodule update` to get it")
ENDIF()

# **********************************
# CMake project configuration export
# **********************************

# Add all targets to the build-tree export set
EXPORT(
    TARGETS tins
    FILE "${PROJECT_BINARY_DIR}/libtinsTargets.cmake"
)

# Export the package for use from the build-tree
# (this registers the build-tree with a global CMake-registry)
EXPORT(PACKAGE libtins)

# Create the libtinsConfig.cmake and libtinsConfigVersion.cmake files
# for the build tree
SET(CONF_INCLUDE_DIRS "${PROJECT_SOURCE_DIR}/include")
CONFIGURE_FILE(
    cmake/libtinsConfig.cmake.in
    "${PROJECT_BINARY_DIR}/libtinsConfig.cmake" @ONLY
)
CONFIGURE_FILE(
    cmake/libtinsConfigVersion.cmake.in
    "${PROJECT_BINARY_DIR}/libtinsConfigVersion.cmake" @ONLY
)
# Install the libtinsConfig.cmake and libtinsConfigVersion.cmake
INSTALL(
    FILES
    "${PROJECT_BINARY_DIR}/libtinsConfig.cmake"
    "${PROJECT_BINARY_DIR}/libtinsConfigVersion.cmake"
    DESTINATION CMake
    COMPONENT dev
)

# Install the export set for use with the install-tree
INSTALL(
    EXPORT libtinsTargets
    DESTINATION CMake
    COMPONENT dev
)
