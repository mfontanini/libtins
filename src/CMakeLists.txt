SET(LIBTINS_INCLUDE_DIR ../include/)

IF(HAVE_PCAP_IMMEDIATE_MODE)
    ADD_DEFINITIONS("-DHAVE_PCAP_IMMEDIATE_MODE=1")
ENDIF()

IF(HAVE_PCAP_TIMESTAMP_PRECISION)
    ADD_DEFINITIONS("-DHAVE_PCAP_TIMESTAMP_PRECISION=1")
ENDIF()

INCLUDE_DIRECTORIES(BEFORE
    ${OPENSSL_INCLUDE_DIR}
    ${PCAP_INCLUDE_DIR}
    ${LIBTINS_INCLUDE_DIR}
    ${PROJECT_BINARY_DIR}/include
)

set(SOURCES
    address_range.cpp
    arp.cpp
    bootp.cpp
    crypto.cpp
    detail/address_helpers.cpp
    detail/icmp_extension_helpers.cpp
    detail/pdu_helpers.cpp
    detail/sequence_number_helpers.cpp
    dhcp.cpp
    dhcpv6.cpp
    dns.cpp
    dot3.cpp
    dot1q.cpp
    eapol.cpp
    ethernetII.cpp
    handshake_capturer.cpp
    hw_address.cpp
    icmp_extension.cpp
    icmp.cpp
    icmpv6.cpp
    ip_reassembler.cpp
    ip.cpp
    ip_address.cpp
    ipv6.cpp
    ipv6_address.cpp
    ipsec.cpp
    llc.cpp
    loopback.cpp
    mpls.cpp
    memory_helpers.cpp
    network_interface.cpp
    packet_sender.cpp
    pdu.cpp
    pdu_iterator.cpp
    pdu_option.cpp
    pppoe.cpp
    radiotap.cpp
    rawpdu.cpp
    rsn_information.cpp
    sll.cpp
    snap.cpp
    stp.cpp
    tcp.cpp
    tcp_ip/ack_tracker.cpp
    tcp_ip/flow.cpp
    tcp_ip/data_tracker.cpp
    tcp_ip/stream.cpp
    tcp_ip/stream_follower.cpp
    tcp_ip/stream_identifier.cpp
    timestamp.cpp
    udp.cpp
    utils/checksum_utils.cpp
    utils/frequency_utils.cpp
    utils/radiotap_parser.cpp
    utils/radiotap_writer.cpp
    utils/routing_utils.cpp
    utils/resolve_utils.cpp
    utils/pdu_utils.cpp
)

set(HEADERS
    ${LIBTINS_INCLUDE_DIR}/tins/address_range.h
    ${LIBTINS_INCLUDE_DIR}/tins/arp.h
    ${LIBTINS_INCLUDE_DIR}/tins/bootp.h
    ${LIBTINS_INCLUDE_DIR}/tins/handshake_capturer.h
    ${LIBTINS_INCLUDE_DIR}/tins/stp.h
    ${LIBTINS_INCLUDE_DIR}/tins/pppoe.h
    ${PROJECT_BINARY_DIR}/include/tins/config.h
    ${LIBTINS_INCLUDE_DIR}/tins/constants.h
    ${LIBTINS_INCLUDE_DIR}/tins/crypto.h
    ${LIBTINS_INCLUDE_DIR}/tins/cxxstd.h
    ${LIBTINS_INCLUDE_DIR}/tins/data_link_type.h
    ${LIBTINS_INCLUDE_DIR}/tins/detail/address_helpers.h
    ${LIBTINS_INCLUDE_DIR}/tins/detail/icmp_extension_helpers.h
    ${LIBTINS_INCLUDE_DIR}/tins/detail/pdu_helpers.h
    ${LIBTINS_INCLUDE_DIR}/tins/detail/sequence_number_helpers.h
    ${LIBTINS_INCLUDE_DIR}/tins/detail/smart_ptr.h
    ${LIBTINS_INCLUDE_DIR}/tins/detail/type_traits.h
    ${LIBTINS_INCLUDE_DIR}/tins/dhcp.h
    ${LIBTINS_INCLUDE_DIR}/tins/dhcpv6.h
    ${LIBTINS_INCLUDE_DIR}/tins/dns.h
    ${LIBTINS_INCLUDE_DIR}/tins/dot3.h
    ${LIBTINS_INCLUDE_DIR}/tins/dot1q.h
    ${LIBTINS_INCLUDE_DIR}/tins/eapol.h
    ${LIBTINS_INCLUDE_DIR}/tins/endianness.h
    ${LIBTINS_INCLUDE_DIR}/tins/ethernetII.h
    ${LIBTINS_INCLUDE_DIR}/tins/exceptions.h
    ${LIBTINS_INCLUDE_DIR}/tins/hw_address.h
    ${LIBTINS_INCLUDE_DIR}/tins/icmp_extension.h
    ${LIBTINS_INCLUDE_DIR}/tins/icmp.h
    ${LIBTINS_INCLUDE_DIR}/tins/icmpv6.h
    ${LIBTINS_INCLUDE_DIR}/tins/ieee802_3.h
    ${LIBTINS_INCLUDE_DIR}/tins/internals.h
    ${LIBTINS_INCLUDE_DIR}/tins/ip_reassembler.h
    ${LIBTINS_INCLUDE_DIR}/tins/ip.h
    ${LIBTINS_INCLUDE_DIR}/tins/ip_address.h
    ${LIBTINS_INCLUDE_DIR}/tins/ipv6.h
    ${LIBTINS_INCLUDE_DIR}/tins/ipv6_address.h
    ${LIBTINS_INCLUDE_DIR}/tins/ipsec.h
    ${LIBTINS_INCLUDE_DIR}/tins/llc.h
    ${LIBTINS_INCLUDE_DIR}/tins/loopback.h
    ${LIBTINS_INCLUDE_DIR}/tins/macros.h
    ${LIBTINS_INCLUDE_DIR}/tins/mpls.h
    ${LIBTINS_INCLUDE_DIR}/tins/memory_helpers.h
    ${LIBTINS_INCLUDE_DIR}/tins/network_interface.h
    ${LIBTINS_INCLUDE_DIR}/tins/packet.h
    ${LIBTINS_INCLUDE_DIR}/tins/packet_sender.h
    ${LIBTINS_INCLUDE_DIR}/tins/pdu.h
    ${LIBTINS_INCLUDE_DIR}/tins/pdu_allocator.h
    ${LIBTINS_INCLUDE_DIR}/tins/pdu_cacher.h
    ${LIBTINS_INCLUDE_DIR}/tins/pdu_iterator.h
    ${LIBTINS_INCLUDE_DIR}/tins/pdu_option.h
    ${LIBTINS_INCLUDE_DIR}/tins/radiotap.h
    ${LIBTINS_INCLUDE_DIR}/tins/rawpdu.h
    ${LIBTINS_INCLUDE_DIR}/tins/rsn_information.h
    ${LIBTINS_INCLUDE_DIR}/tins/sll.h
    ${LIBTINS_INCLUDE_DIR}/tins/small_uint.h
    ${LIBTINS_INCLUDE_DIR}/tins/snap.h
    ${LIBTINS_INCLUDE_DIR}/tins/tcp.h
    ${LIBTINS_INCLUDE_DIR}/tins/tcp_ip/ack_tracker.h
    ${LIBTINS_INCLUDE_DIR}/tins/tcp_ip/flow.h
    ${LIBTINS_INCLUDE_DIR}/tins/tcp_ip/data_tracker.h
    ${LIBTINS_INCLUDE_DIR}/tins/tcp_ip/stream.h
    ${LIBTINS_INCLUDE_DIR}/tins/tcp_ip/stream_follower.h
    ${LIBTINS_INCLUDE_DIR}/tins/tcp_ip/stream_identifier.h
    ${LIBTINS_INCLUDE_DIR}/tins/timestamp.h
    ${LIBTINS_INCLUDE_DIR}/tins/tins.h
    ${LIBTINS_INCLUDE_DIR}/tins/udp.h
    ${LIBTINS_INCLUDE_DIR}/tins/utils.h
    ${LIBTINS_INCLUDE_DIR}/tins/utils/checksum_utils.h
    ${LIBTINS_INCLUDE_DIR}/tins/utils/frequency_utils.h
    ${LIBTINS_INCLUDE_DIR}/tins/utils/radiotap_parser.h
    ${LIBTINS_INCLUDE_DIR}/tins/utils/radiotap_writer.h
    ${LIBTINS_INCLUDE_DIR}/tins/utils/routing_utils.h
    ${LIBTINS_INCLUDE_DIR}/tins/utils/resolve_utils.h
    ${LIBTINS_INCLUDE_DIR}/tins/utils/pdu_utils.h
)

SET(DOT11_DEPENDENT_SOURCES
    dot11/dot11_base.cpp
    dot11/dot11_data.cpp
    dot11/dot11_mgmt.cpp
    dot11/dot11_beacon.cpp
    dot11/dot11_assoc.cpp
    dot11/dot11_auth.cpp
    dot11/dot11_probe.cpp
    dot11/dot11_control.cpp
)

SET(DOT11_DEPENDENT_HEADERS
    ${LIBTINS_INCLUDE_DIR}/tins/dot11.h
    ${LIBTINS_INCLUDE_DIR}/tins/dot11/dot11_base.h
    ${LIBTINS_INCLUDE_DIR}/tins/dot11/dot11_data.h
    ${LIBTINS_INCLUDE_DIR}/tins/dot11/dot11_mgmt.h
    ${LIBTINS_INCLUDE_DIR}/tins/dot11/dot11_beacon.h
    ${LIBTINS_INCLUDE_DIR}/tins/dot11/dot11_assoc.h
    ${LIBTINS_INCLUDE_DIR}/tins/dot11/dot11_auth.h
    ${LIBTINS_INCLUDE_DIR}/tins/dot11/dot11_probe.h
    ${LIBTINS_INCLUDE_DIR}/tins/dot11/dot11_control.h
)

IF(LIBTINS_ENABLE_DOT11)
    SET(SOURCES ${SOURCES} ${DOT11_DEPENDENT_SOURCES})
    SET(HEADERS ${HEADERS} ${DOT11_DEPENDENT_HEADERS})
ENDIF()

SET(PCAP_DEPENDENT_SOURCES
    sniffer.cpp
    packet_writer.cpp
    pktap.cpp
    tcp_stream.cpp
    offline_packet_filter.cpp
    ppi.cpp
)

SET(PCAP_DEPENDENT_HEADERS
    ${LIBTINS_INCLUDE_DIR}/tins/offline_packet_filter.h
    ${LIBTINS_INCLUDE_DIR}/tins/packet_writer.h
    ${LIBTINS_INCLUDE_DIR}/tins/pktap.h
    ${LIBTINS_INCLUDE_DIR}/tins/ppi.h
    ${LIBTINS_INCLUDE_DIR}/tins/sniffer.h
    ${LIBTINS_INCLUDE_DIR}/tins/tcp_stream.h
)

IF(LIBTINS_ENABLE_PCAP)
    SET(SOURCES ${SOURCES} ${PCAP_DEPENDENT_SOURCES})
    SET(HEADERS ${HEADERS} ${PCAP_DEPENDENT_HEADERS})
ENDIF() 

ADD_LIBRARY( 
    tins ${LIBTINS_TYPE}
    ${SOURCES}
    ${HEADERS}
)

TARGET_LINK_LIBRARIES(tins ${PCAP_LIBRARY} ${OPENSSL_LIBRARIES} ${LIBTINS_OS_LIBS})

SET_TARGET_PROPERTIES(tins PROPERTIES OUTPUT_NAME tins)
SET_TARGET_PROPERTIES(tins PROPERTIES VERSION ${LIBTINS_VERSION} SOVERSION ${LIBTINS_VERSION} )

# Install instructions for this target
INSTALL( 
    TARGETS tins
    EXPORT libtinsTargets
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    COMPONENT dev
)

MACRO(INSTALL_HEADERS_WITH_DIRECTORY HEADER_LIST)
    FOREACH(HEADER ${HEADERS})
        # Extract directory name and remove leading '../'
        get_filename_component(DIR ${HEADER} PATH)
        STRING(REGEX REPLACE "^\\.\\.\\/" "" DIR ${DIR})
        INSTALL(FILES ${HEADER} DESTINATION ${DIR})
    ENDFOREACH(HEADER)
ENDMACRO()

INSTALL_HEADERS_WITH_DIRECTORY(${HEADERS})
