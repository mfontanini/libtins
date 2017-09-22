SET(LIBTINS_INCLUDE_DIR ../include/)

IF(HAVE_PCAP_IMMEDIATE_MODE)
    ADD_DEFINITIONS("-DHAVE_PCAP_IMMEDIATE_MODE=1")
ENDIF()

IF(HAVE_PCAP_TIMESTAMP_PRECISION)
    ADD_DEFINITIONS("-DHAVE_PCAP_TIMESTAMP_PRECISION=1")
ENDIF()

INCLUDE_DIRECTORIES(
    ${LIBTINS_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
    ${PCAP_INCLUDE_DIR}
)

set(SOURCES
    arp.cpp
    bootp.cpp
    handshake_capturer.cpp
    stp.cpp
    pppoe.cpp
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
    radiotap.cpp
    address_range.cpp
    pdu_iterator.cpp
    pdu_option.cpp
    rawpdu.cpp
    rsn_information.cpp
    sll.cpp
    snap.cpp
    tcp.cpp
    tcp_ip/ack_tracker.cpp
    tcp_ip/flow.cpp
    tcp_ip/data_tracker.cpp
    tcp_ip/stream.cpp
    tcp_ip/stream_follower.cpp
    tcp_ip/stream_identifier.cpp
    timestamp.cpp
    udp.cpp
    dot11/dot11_base.cpp
    dot11/dot11_data.cpp
    dot11/dot11_mgmt.cpp
    dot11/dot11_beacon.cpp
    dot11/dot11_assoc.cpp
    dot11/dot11_auth.cpp
    dot11/dot11_probe.cpp
    dot11/dot11_control.cpp
    utils/checksum_utils.cpp
    utils/frequency_utils.cpp
    utils/radiotap_parser.cpp
    utils/radiotap_writer.cpp
    utils/routing_utils.cpp
    utils/resolve_utils.cpp
    utils/pdu_utils.cpp
)

SET(PCAP_DEPENDENT_SOURCES
    sniffer.cpp
    packet_writer.cpp
    pktap.cpp
    tcp_stream.cpp
    offline_packet_filter.cpp
    ppi.cpp
)

IF(LIBTINS_ENABLE_PCAP)
    SET(SOURCES ${SOURCES} ${PCAP_DEPENDENT_SOURCES})
ENDIF() 

ADD_LIBRARY( 
    tins ${LIBTINS_TYPE}
    ${SOURCES}
)

TARGET_LINK_LIBRARIES(tins ${PCAP_LIBRARY} ${OPENSSL_LIBRARIES} ${LIBTINS_OS_LIBS})

SET_TARGET_PROPERTIES(tins PROPERTIES OUTPUT_NAME tins)
SET_TARGET_PROPERTIES(tins PROPERTIES VERSION ${LIBTINS_VERSION} SOVERSION ${LIBTINS_VERSION} )

# Install instructions for this target
INSTALL( 
    TARGETS tins
    EXPORT libtinsTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    COMPONENT dev
)
