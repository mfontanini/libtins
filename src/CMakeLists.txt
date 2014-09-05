SET(LIBTINS_INCLUDE_DIR ../include)

INCLUDE_DIRECTORIES(
    ${LIBTINS_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
    ${PCAP_INCLUDE_DIR}
)

ADD_LIBRARY( 
    tins ${LIBTINS_TYPE}
    arp.cpp
    bootp.cpp
    handshake_capturer.cpp
    stp.cpp
    pppoe.cpp
    crypto.cpp
    dhcp.cpp
    dhcpv6.cpp
    dns.cpp
    dot3.cpp
    dot1q.cpp
    eapol.cpp
    ethernetII.cpp
    icmp.cpp
    icmpv6.cpp
    internals.cpp
    ip_reassembler.cpp
    ip.cpp
    ip_address.cpp
    ipv6.cpp
    ipv6_address.cpp
    ipsec.cpp
    llc.cpp
    loopback.cpp
    network_interface.cpp
    offline_packet_filter.cpp
    packet_sender.cpp
    packet_writer.cpp
    ppi.cpp
    pdu.cpp
    radiotap.cpp
    address_range.cpp
    rawpdu.cpp
    rsn_information.cpp
    sll.cpp
    snap.cpp
    sniffer.cpp
    tcp.cpp
    tcp_stream.cpp
    udp.cpp
    utils.cpp
    dot11/dot11_base.cpp
    dot11/dot11_data.cpp
    dot11/dot11_mgmt.cpp
    dot11/dot11_beacon.cpp
    dot11/dot11_assoc.cpp
    dot11/dot11_auth.cpp
    dot11/dot11_probe.cpp
    dot11/dot11_control.cpp
)

TARGET_LINK_LIBRARIES(tins ${PCAP_LIBRARY} ${OPENSSL_LIBRARIES} ${LIBTINS_OS_LIBS})

SET_TARGET_PROPERTIES(tins PROPERTIES OUTPUT_NAME tins )
SET_TARGET_PROPERTIES(tins PROPERTIES VERSION ${LIBTINS_VERSION} SOVERSION ${LIBTINS_VERSION} )

# Install instructions for this target
INSTALL( 
    TARGETS tins
    EXPORT libtinsTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    COMPONENT dev
)
