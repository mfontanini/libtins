FIND_PACKAGE(libtins QUIET)
FIND_PACKAGE(Threads QUIET)

IF(libtins_FOUND)
    SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/examples)
    INCLUDE_DIRECTORIES(
        ${LIBTINS_INCLUDE_DIRS}
        ${PCAP_INCLUDE_DIR}
    )
    LINK_LIBRARIES(${LIBTINS_LIBRARIES})

    IF(HAVE_CXX11)
        SET(LIBTINS_CXX11_EXAMPLES
            arpmonitor
            dns_queries
            dns_spoof
            dns_stats
            wps_detect
            traceroute
            interfaces_info
            icmp_responses
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
        route_table
    )

    ADD_EXECUTABLE(arpspoofing EXCLUDE_FROM_ALL arpspoofing.cpp)
    ADD_EXECUTABLE(route_table EXCLUDE_FROM_ALL route_table.cpp)
    IF(HAVE_CXX11)
        ADD_EXECUTABLE(arpmonitor EXCLUDE_FROM_ALL arpmonitor.cpp)
        ADD_EXECUTABLE(dns_queries EXCLUDE_FROM_ALL dns_queries.cpp)
        ADD_EXECUTABLE(dns_spoof EXCLUDE_FROM_ALL dns_spoof.cpp)
        ADD_EXECUTABLE(wps_detect EXCLUDE_FROM_ALL wps_detect.cpp)
        ADD_EXECUTABLE(interfaces_info EXCLUDE_FROM_ALL interfaces_info.cpp)
        ADD_EXECUTABLE(icmp_responses EXCLUDE_FROM_ALL icmp_responses.cpp)
    ENDIF(HAVE_CXX11)

    ADD_EXECUTABLE(beacon_display EXCLUDE_FROM_ALL beacon_display.cpp)

    if(THREADS_FOUND)
        IF(HAVE_CXX11)
            ADD_EXECUTABLE(traceroute EXCLUDE_FROM_ALL traceroute.cpp)
            ADD_EXECUTABLE(dns_stats EXCLUDE_FROM_ALL dns_stats.cpp)
            TARGET_LINK_LIBRARIES(traceroute ${CMAKE_THREAD_LIBS_INIT})
            TARGET_LINK_LIBRARIES(dns_stats ${CMAKE_THREAD_LIBS_INIT})
        ENDIF(HAVE_CXX11)
        IF(WIN32)
            MESSAGE(WARNING "Disabling portscan example since it doesn't compile on Windows.")
        ELSE()
            ADD_EXECUTABLE(portscan EXCLUDE_FROM_ALL portscan.cpp)
            TARGET_LINK_LIBRARIES(portscan ${CMAKE_THREAD_LIBS_INIT})
        ENDIF()
    ELSE()
        MESSAGE(WARNING "Disabling portscan and traceroute examples since pthreads library was not found.")
    ENDIF()
ELSE(libtins_FOUND)
    MESSAGE(
        WARNING 
        "Disabling examples since libtins is not installed. "
        "Run cmake again once it is installed in order to compile them."
    )
ENDIF(libtins_FOUND)
