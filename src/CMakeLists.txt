OPTION(LIBTINS_BUILD_SHARED "Build libtins as a shared library." ON)
IF(LIBTINS_BUILD_SHARED)
  SET(LIBTINS_TYPE SHARED)
ELSE(LIBTINS_BUILD_SHARED)
  SET(LIBTINS_TYPE STATIC)
ENDIF(LIBTINS_BUILD_SHARED)


SET(LIBTINS_INCLUDE_DIR ../include)

INCLUDE_DIRECTORIES(${LIBTINS_INCLUDE_DIR})

SET(PUBLIC_HEADERS
    ${LIBTINS_INCLUDE_DIR}/internals.h
    ${LIBTINS_INCLUDE_DIR}/dhcpv6.h
    ${LIBTINS_INCLUDE_DIR}/dot11.h
    ${LIBTINS_INCLUDE_DIR}/dot1q.h
    ${LIBTINS_INCLUDE_DIR}/dot3.h
    ${LIBTINS_INCLUDE_DIR}/small_uint.h
    ${LIBTINS_INCLUDE_DIR}/ip.h
    ${LIBTINS_INCLUDE_DIR}/ipsec.h
    ${LIBTINS_INCLUDE_DIR}/eapol.h
    ${LIBTINS_INCLUDE_DIR}/tcp_stream.h
    ${LIBTINS_INCLUDE_DIR}/pppoe.h
    ${LIBTINS_INCLUDE_DIR}/handshake_capturer.h
    ${LIBTINS_INCLUDE_DIR}/ipv6.h
    ${LIBTINS_INCLUDE_DIR}/icmpv6.h
    ${LIBTINS_INCLUDE_DIR}/ieee802_3.h
    ${LIBTINS_INCLUDE_DIR}/endianness.h
    ${LIBTINS_INCLUDE_DIR}/rsn_information.h
    ${LIBTINS_INCLUDE_DIR}/loopback.h
    ${LIBTINS_INCLUDE_DIR}/ethernetII.h
    ${LIBTINS_INCLUDE_DIR}/crypto.h
    ${LIBTINS_INCLUDE_DIR}/packet.h
    ${LIBTINS_INCLUDE_DIR}/llc.h
    ${LIBTINS_INCLUDE_DIR}/ip_reassembler.h
    ${LIBTINS_INCLUDE_DIR}/icmp.h
    ${LIBTINS_INCLUDE_DIR}/hw_address.h
    ${LIBTINS_INCLUDE_DIR}/packet_writer.h
    ${LIBTINS_INCLUDE_DIR}/macros.h
    ${LIBTINS_INCLUDE_DIR}/arp.h
    ${LIBTINS_INCLUDE_DIR}/ip_address.h
    ${LIBTINS_INCLUDE_DIR}/pdu.h
    ${LIBTINS_INCLUDE_DIR}/packet_sender.h
    ${LIBTINS_INCLUDE_DIR}/bootp.h
    ${LIBTINS_INCLUDE_DIR}/network_interface.h
    ${LIBTINS_INCLUDE_DIR}/sll.h
    ${LIBTINS_INCLUDE_DIR}/ppi.h
    ${LIBTINS_INCLUDE_DIR}/radiotap.h
    ${LIBTINS_INCLUDE_DIR}/dns.h
    ${LIBTINS_INCLUDE_DIR}/rawpdu.h
    ${LIBTINS_INCLUDE_DIR}/sniffer.h
    ${LIBTINS_INCLUDE_DIR}/snap.h
    ${LIBTINS_INCLUDE_DIR}/pdu_cacher.h
    ${LIBTINS_INCLUDE_DIR}/dhcp.h
    ${LIBTINS_INCLUDE_DIR}/timestamp.h
    ${LIBTINS_INCLUDE_DIR}/tcp.h
    ${LIBTINS_INCLUDE_DIR}/pdu_option.h
    ${LIBTINS_INCLUDE_DIR}/tins.h
    ${LIBTINS_INCLUDE_DIR}/udp.h
    ${LIBTINS_INCLUDE_DIR}/ipv6_address.h 
    ${LIBTINS_INCLUDE_DIR}/constants.h
    ${LIBTINS_INCLUDE_DIR}/utils.h
    ${LIBTINS_INCLUDE_DIR}/cxxstd.h
    ${LIBTINS_INCLUDE_DIR}/stp.h
    ${LIBTINS_INCLUDE_DIR}/exceptions.h
    ${LIBTINS_INCLUDE_DIR}/address_range.h
    ${LIBTINS_INCLUDE_DIR}/pdu_allocator.h
    ${LIBTINS_INCLUDE_DIR}/dot11/dot11_base.h
    ${LIBTINS_INCLUDE_DIR}/dot11/dot11_beacon.h
    ${LIBTINS_INCLUDE_DIR}/dot11/dot11_data.h
    ${LIBTINS_INCLUDE_DIR}/dot11/dot11_mgmt.h
    ${LIBTINS_INCLUDE_DIR}/dot11/dot11_assoc.h
    ${LIBTINS_INCLUDE_DIR}/dot11/dot11_auth.h
    ${LIBTINS_INCLUDE_DIR}/dot11/dot11_probe.h
    ${LIBTINS_INCLUDE_DIR}/dot11/dot11_control.h
    ${LIBTINS_INCLUDE_DIR}/config.h
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

TARGET_LINK_LIBRARIES(tins pcap)

SET_TARGET_PROPERTIES(tins PROPERTIES OUTPUT_NAME tins )
SET_TARGET_PROPERTIES(tins PROPERTIES VERSION ${LIBTINS_CPP_VERSION} SOVERSION ${LIBTINS_CPP_VERSION} )
SET_TARGET_PROPERTIES(tins PROPERTIES PUBLIC_HEADER "${PUBLIC_HEADERS}" )

# Install instructions for this target
INSTALL( 
    TARGETS tins
    EXPORT libtinsTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    PUBLIC_HEADER DESTINATION include/tins COMPONENT dev
)
