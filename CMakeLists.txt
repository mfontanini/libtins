CMAKE_MINIMUM_REQUIRED(VERSION 2.8.1)
PROJECT(libtins)

# Compile in release mode by default
IF(NOT CMAKE_BUILD_TYPE)
    MESSAGE(STATUS "Setting build type to 'RelWithDebInfo' as none was specified.")
    SET(CMAKE_BUILD_TYPE RelWithDebInfo) 
ELSE(NOT CMAKE_BUILD_TYPE)
    MESSAGE(STATUS "Using specified '${CMAKE_BUILD_TYPE}' build type.")
ENDIF(NOT CMAKE_BUILD_TYPE)

# Default compilation settings
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")

# Build output checks
OPTION(LIBTINS_BUILD_SHARED "Build libtins as a shared library." ON)
IF(LIBTINS_BUILD_SHARED)
  MESSAGE(STATUS "Build will generate a shared library.")
  MESSAGE(STATUS "Use LIBTINS_BUILD_SHARED=0 to perform a static build")
  SET(LIBTINS_TYPE SHARED)
ELSE(LIBTINS_BUILD_SHARED)
  MESSAGE(STATUS "Build will generate a static library.")
  SET(LIBTINS_TYPE STATIC)
ENDIF(LIBTINS_BUILD_SHARED)

# The version number.
SET(LIBTINS_VERSION_MAJOR 3)
SET(LIBTINS_VERSION_MINOR 0)
SET(LIBTINS_CPP_VERSION "${LIBTINS_VERSION_MAJOR}.${LIBTINS_VERSION_MINOR}")

# Required Packages
SET(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

# Look for libpcap
FIND_PACKAGE(PCAP REQUIRED)

# Compilation options
OPTION(LIBTINS_ENABLE_CXX11 "Compile libtins with c++11 features" OFF)
IF(LIBTINS_ENABLE_CXX11)
    SET(HAVE_CXX11 ON)
    INCLUDE(CheckCXX11Features)
    IF(CXX11_COMPILER_FLAGS AND HAS_CXX11_NULLPTR AND HAS_CXX11_RVALUE_REFERENCES)
        SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CXX11_COMPILER_FLAGS}")
    ELSE(CXX11_COMPILER_FLAGS AND HAS_CXX11_NULLPTR AND HAS_CXX11_RVALUE_REFERENCES)
        MESSAGE(FATAL_ERROR "C++11 features requested but the compiler does not support them.")
    ENDIF(CXX11_COMPILER_FLAGS AND HAS_CXX11_NULLPTR AND HAS_CXX11_RVALUE_REFERENCES)
ELSE(LIBTINS_ENABLE_CXX11)
    MESSAGE(STATUS "Disabling C++11 features. Use LIBTINS_ENABLE_CXX11=1 to enable them.")
ENDIF(LIBTINS_ENABLE_CXX11)

OPTION(LIBTINS_ENABLE_DOT11 "Compile libtins with IEEE 802.11 support" ON)
OPTION(LIBTINS_ENABLE_WPA2 "Compile libtins with WPA2 decryption features (requires OpenSSL)" ON)
IF(LIBTINS_ENABLE_DOT11)
    SET(HAVE_DOT11 ON)
    MESSAGE(STATUS "Enabling IEEE 802.11 support.")
    IF(LIBTINS_ENABLE_WPA2)
        FIND_PACKAGE(OpenSSL REQUIRED)
        SET(HAVE_WPA2_DECRYPTION ON)
        MESSAGE(STATUS "Enabling WPA2 decryption support.")
    ELSE(LIBTINS_ENABLE_WPA2)
        MESSAGE(STATUS "Disabling WPA2 decryption support.")
    ENDIF(LIBTINS_ENABLE_WPA2)
ENDIF(LIBTINS_ENABLE_DOT11)

SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
SET(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)

# Congiguration file
CONFIGURE_FILE(
  "${PROJECT_SOURCE_DIR}/include/config.h.in"
  "${PROJECT_SOURCE_DIR}/include/config.h"
)

ENABLE_TESTING()
ADD_SUBDIRECTORY(include)
ADD_SUBDIRECTORY(src)
ADD_SUBDIRECTORY(tests)

# Add all targets to the build-tree export set
EXPORT(TARGETS tins
       FILE "${PROJECT_BINARY_DIR}/libtinsTargets.cmake")

# Export the package for use from the build-tree
# (this registers the build-tree with a global CMake-registry)
EXPORT(PACKAGE libtins)
# Create the libtinsConfig.cmake and libtinsConfigVersion.cmake files
# for the build tree
SET(CONF_INCLUDE_DIRS "${PROJECT_SOURCE_DIR}/include")
CONFIGURE_FILE(libtinsConfig.cmake.in
               "${PROJECT_BINARY_DIR}/libtinsConfig.cmake" @ONLY)
CONFIGURE_FILE(libtinsConfigVersion.cmake.in
               "${PROJECT_BINARY_DIR}/libtinsConfigVersion.cmake" @ONLY)
# Install the libtinsConfig.cmake and libtinsConfigVersion.cmake
INSTALL(FILES
       "${PROJECT_BINARY_DIR}/libtinsConfig.cmake"
       "${PROJECT_BINARY_DIR}/libtinsConfigVersion.cmake"
       DESTINATION CMake
       COMPONENT dev)
# Install the export set for use with the install-tree
INSTALL(EXPORT libtinsTargets
        DESTINATION CMake
        COMPONENT dev)
