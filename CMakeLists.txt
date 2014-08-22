cmake_minimum_required(VERSION 2.8.1)
project(libtins)

# The version number.
SET(LIBTINS_VERSION_MAJOR 3)
SET(LIBTINS_VERSION_MINOR 0)
SET(LIBTINS_CPP_VERSION "${LIBTINS_VERSION_MAJOR}.${LIBTINS_VERSION_MINOR}")

# Required Packages
SET(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

FIND_PACKAGE(PCAP REQUIRED)

# Default compilation settings
SET(CMAKE_CXX_FLAGS "-Wall ${CXX11_COMPILER_FLAGS}")

# Compilation options
OPTION(LIBTINS_ENABLE_CXX11 "Compile libtins with c++11 features" OFF)
IF(LIBTINS_ENABLE_CXX11)
    SET(HAVE_CXX11 ON)
    INCLUDE(CheckCXX11Features)
    IF(CXX11_COMPILER_FLAGS AND HAS_CXX11_NULLPTR AND HAS_CXX11_AUTO)
        SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CXX11_COMPILER_FLAGS}")
    ELSE(CXX11_COMPILER_FLAGS AND HAS_CXX11_NULLPTR AND HAS_CXX11_AUTO)
        MESSAGE(FATAL_ERROR "C++11 features requested but the compiler does not support them!")
    ENDIF(CXX11_COMPILER_FLAGS AND HAS_CXX11_NULLPTR AND HAS_CXX11_AUTO)
ENDIF(LIBTINS_ENABLE_CXX11)

OPTION(LIBTINS_ENABLE_DOT11 "Compile libtins with IEEE 802.11 support" ON)
OPTION(LIBTINS_ENABLE_WPA2 "Compile libtins with WPA2 decryption features (requires OpenSSL)" OFF)
IF(LIBTINS_ENABLE_DOT11)
    SET(HAVE_DOT11 ON)
    IF(LIBTINS_ENABLE_WPA2)
        FIND_PACKAGE(OpenSSL REQUIRED)
        SET(HAVE_WPA2_DECRYPTION ON)
    ENDIF(LIBTINS_ENABLE_WPA2)
ENDIF(LIBTINS_ENABLE_DOT11)

SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
SET(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)

# Congiguration file
CONFIGURE_FILE(
  "${PROJECT_SOURCE_DIR}/include/config.h.in"
  "${PROJECT_SOURCE_DIR}/include/config.h"
)

ADD_SUBDIRECTORY(include)
ADD_SUBDIRECTORY(src)

# Add all targets to the build-tree export set
EXPORT(TARGETS tins
       FILE "${PROJECT_BINARY_DIR}/libtinsTargets.cmake")
# Export the package for use from the build-tree
# (this registers the build-tree with a global CMake-registry)
EXPORT(PACKAGE libtins)
# Create the jsoncppConfig.cmake and libtinsConfigVersion.cmake files
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
