# Use libtins' include directories + test include directories
INCLUDE_DIRECTORIES(
    ${PROJECT_SOURCE_DIR}/include/tins/ 
    ../include/
    ${GOOGLETEST_INCLUDE}
    ${PCAP_INCLUDE_DIR}
)

# Find pthread library
FIND_PACKAGE(Threads REQUIRED)

LINK_DIRECTORIES(
    ${GOOGLETEST_LIBRARY}
)
# Link against GoogleTest, libtins and pthread.
# Pthread is required by GoogleTest
LINK_LIBRARIES(
    gtest
    gtest_main
    tins 
    ${CMAKE_THREAD_LIBS_INIT}
    ${PCAP_LIBRARY}
)

ADD_CUSTOM_TARGET(tests)

MACRO(CREATE_TEST test_name)
    STRING(REPLACE "/" "_" binary_name ${test_name})
    SET(binary_name "${binary_name}_test")
    ADD_EXECUTABLE(${binary_name} EXCLUDE_FROM_ALL "${test_name}_test.cpp")
    ADD_TEST(${test_name} ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${binary_name})
    ADD_DEPENDENCIES(tests ${binary_name})
ENDMACRO()

# Tests

CREATE_TEST(address_range)
CREATE_TEST(allocators)
CREATE_TEST(arp)
CREATE_TEST(dhcp)
CREATE_TEST(dhcpv6)
CREATE_TEST(dns)
CREATE_TEST(dot11/ack)
CREATE_TEST(dot11/assoc_request)
CREATE_TEST(dot11/assoc_response)
CREATE_TEST(dot11/authentication)
CREATE_TEST(dot11/beacon)
CREATE_TEST(dot11/block_ack_request)
CREATE_TEST(dot11/cf_end)
CREATE_TEST(dot11/cf_end_ack)
CREATE_TEST(dot11/data)
CREATE_TEST(dot11/deauthentication)
CREATE_TEST(dot11/disassoc)
CREATE_TEST(dot11/dot11)
CREATE_TEST(dot11/probe_request)
CREATE_TEST(dot11/probe_response)
CREATE_TEST(dot11/ps_poll)
CREATE_TEST(dot11/reassoc_request)
CREATE_TEST(dot11/reassoc_response)
CREATE_TEST(dot11/rts)
CREATE_TEST(dot1q)
CREATE_TEST(ethernet)
CREATE_TEST(hw_address)
CREATE_TEST(icmp_extension)
CREATE_TEST(icmp)
CREATE_TEST(icmpv6)
CREATE_TEST(ip)
CREATE_TEST(ip_reassembler)
CREATE_TEST(ip_address)
CREATE_TEST(ipsec)
CREATE_TEST(ipv6)
CREATE_TEST(ipv6_address)
CREATE_TEST(llc)
CREATE_TEST(loopback)
CREATE_TEST(matches_response)
CREATE_TEST(mpls)
CREATE_TEST(network_interface)
CREATE_TEST(offline_packet_filter)
CREATE_TEST(pdu)
CREATE_TEST(ppi)
CREATE_TEST(pppoe)
CREATE_TEST(radiotap)
CREATE_TEST(rc4_eapol)
CREATE_TEST(rsn_eapol)
CREATE_TEST(sll)
CREATE_TEST(snap)
CREATE_TEST(stp)
CREATE_TEST(tcp)
CREATE_TEST(tcp_ip)
CREATE_TEST(tcp_stream)
CREATE_TEST(udp)
CREATE_TEST(utils)
CREATE_TEST(wep_decrypt)

IF(LIBTINS_ENABLE_WPA2)
    CREATE_TEST(wpa2_decrypt)
ENDIF()