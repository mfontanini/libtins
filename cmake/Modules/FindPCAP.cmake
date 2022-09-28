# - Try to find libpcap include dirs and libraries
#
# Usage of this module as follows:
#
#     find_package(PCAP)
#
# Variables used by this module, they can change the default behaviour and need
# to be set before calling find_package:
#
#  PCAP_ROOT_DIR             Set this variable to the root installation of
#                            libpcap if the module has problems finding the
#                            proper installation path.
#
# Variables defined by this module:
#
#  PCAP_FOUND                System has libpcap, include and library dirs found
#  PCAP_INCLUDE_DIR          The libpcap include directories.
#  PCAP_LIBRARY              The libpcap library (possibly includes a thread
#                            library e.g. required by pf_ring's libpcap)
#  HAVE_PF_RING              If a found version of libpcap supports PF_RING
#  HAVE_PCAP_IMMEDIATE_MODE  If the version of libpcap found supports immediate mode

find_path(PCAP_ROOT_DIR
    NAMES include/pcap.h
)

find_path(PCAP_INCLUDE_DIR
    NAMES pcap.h
    HINTS ${PCAP_ROOT_DIR}/include
)

set (HINT_DIR ${PCAP_ROOT_DIR}/lib)

# On x64 windows, we should look also for the .lib at /lib/x64/
# as this is the default path for the WinPcap developer's pack
if (${CMAKE_SIZEOF_VOID_P} EQUAL 8 AND WIN32)
    set (HINT_DIR ${PCAP_ROOT_DIR}/lib/x64/ ${HINT_DIR})
endif ()

find_library(PCAP_LIBRARY
    NAMES pcap wpcap
    HINTS ${HINT_DIR}
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PCAP DEFAULT_MSG
    PCAP_LIBRARY
    PCAP_INCLUDE_DIR
)

include(CheckCXXSourceCompiles)
set(CMAKE_REQUIRED_LIBRARIES ${PCAP_LIBRARY})
check_cxx_source_compiles("int main() { return 0; }" PCAP_LINKS_SOLO)
set(CMAKE_REQUIRED_LIBRARIES)

# check if linking against libpcap also needs to link against a thread library
if (NOT PCAP_LINKS_SOLO)
    find_package(Threads)
    if (THREADS_FOUND)
        set(CMAKE_REQUIRED_LIBRARIES ${PCAP_LIBRARY} ${CMAKE_THREAD_LIBS_INIT})
        check_cxx_source_compiles("int main() { return 0; }" PCAP_NEEDS_THREADS)
        set(CMAKE_REQUIRED_LIBRARIES)
    endif (THREADS_FOUND)
    if (THREADS_FOUND AND PCAP_NEEDS_THREADS)
        set(_tmp ${PCAP_LIBRARY} ${CMAKE_THREAD_LIBS_INIT})
        list(REMOVE_DUPLICATES _tmp)
        set(PCAP_LIBRARY ${_tmp}
            CACHE STRING "Libraries needed to link against libpcap" FORCE)
    else (THREADS_FOUND AND PCAP_NEEDS_THREADS)
        message(FATAL_ERROR "Couldn't determine how to link against libpcap")
    endif (THREADS_FOUND AND PCAP_NEEDS_THREADS)
endif (NOT PCAP_LINKS_SOLO)

include(CheckFunctionExists)
set(CMAKE_REQUIRED_LIBRARIES ${PCAP_LIBRARY})
check_function_exists(pcap_get_pfring_id HAVE_PF_RING)
check_function_exists(pcap_set_immediate_mode HAVE_PCAP_IMMEDIATE_MODE)
check_function_exists(pcap_set_tstamp_precision HAVE_PCAP_TIMESTAMP_PRECISION)
set(CMAKE_REQUIRED_LIBRARIES)

mark_as_advanced(
    PCAP_ROOT_DIR
    PCAP_INCLUDE_DIR
    PCAP_LIBRARY
)
