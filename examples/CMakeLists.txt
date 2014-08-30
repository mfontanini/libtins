FIND_PACKAGE(libtins QUIET)
FIND_PACKAGE(Threads QUIET)

IF(libtins_FOUND)
    SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/examples)
    INCLUDE_DIRECTORIES(${LIBTINS_INCLUDE_DIRS})
    LINK_LIBRARIES(${LIBTINS_LIBRARIES})

    IF(HAVE_CXX11)
        SET(LIBTINS_CXX11_EXAMPLES
            arpmonitor
            dns_queries
            dns_spoof
            dns_stats
            wps_detect
            traceroute
        )
    ELSE(HAVE_CXX11)
        MESSAGE(WARNING "Disabling some examples since C++11 support is disabled.")
    ENDIF(HAVE_CXX11)

    ADD_CUSTOM_TARGET(
        examples DEPENDS
        arpspoofing
        ${LIBTINS_CXX11_EXAMPLES}
        beacon_display
        portscan
    )

    ADD_EXECUTABLE(arpspoofing EXCLUDE_FROM_ALL arpspoofing.cpp)
    IF(HAVE_CXX11)
        ADD_EXECUTABLE(arpmonitor EXCLUDE_FROM_ALL arpmonitor.cpp)
        ADD_EXECUTABLE(dns_queries EXCLUDE_FROM_ALL dns_queries.cpp)
        ADD_EXECUTABLE(dns_spoof EXCLUDE_FROM_ALL dns_spoof.cpp)
        ADD_EXECUTABLE(dns_stats EXCLUDE_FROM_ALL dns_stats.cpp)
        ADD_EXECUTABLE(wps_detect EXCLUDE_FROM_ALL wps_detect.cpp)
    ENDIF(HAVE_CXX11)

    ADD_EXECUTABLE(beacon_display EXCLUDE_FROM_ALL beacon_display.cpp)

    if(THREADS_FOUND)
        IF(HAVE_CXX11)
            ADD_EXECUTABLE(traceroute EXCLUDE_FROM_ALL traceroute.cpp)
            TARGET_LINK_LIBRARIES(traceroute ${CMAKE_THREAD_LIBS_INIT})
        ENDIF(HAVE_CXX11)

        ADD_EXECUTABLE(portscan EXCLUDE_FROM_ALL portscan.cpp)
        TARGET_LINK_LIBRARIES(portscan ${CMAKE_THREAD_LIBS_INIT})
    ELSE(THREADS_FOUND)
        MESSAGE(WARNING "Disabling portscan and traceroute examples since pthreads library was not found.")
    ENDIF(THREADS_FOUND)
ELSE(libtins_FOUND)
    MESSAGE(
        WARNING 
        "Disabling examples since libtins is not installed. "
        "Run cmake again once it is installed in order to compile them."
    )
ENDIF(libtins_FOUND)
