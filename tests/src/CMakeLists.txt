# Use libtins' include directories + test include directories
INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/include/ ../include/)

# Find pthread library
FIND_PACKAGE(Threads REQUIRED)

# Link against GoogleTest, libtins and pthread.
# Pthread is required by GoogleTest
LINK_LIBRARIES(
    ${GTEST_LIBRARIES} 
    ${GTEST_MAIN_LIBRARY} 
    tins 
    ${CMAKE_THREAD_LIBS_INIT}
)

# Add tests target
ADD_CUSTOM_TARGET(
    tests DEPENDS
    AddressRangeTest
    AllocatorsTest
    ArpTest
    DHCPTest
    DHCPv6Test
    DNSTest
    Dot11AckTest
    Dot11AssocRequestTest
    Dot11AssocResponseTest
    Dot11AuthenticationTest
    Dot11BeaconTest
    Dot11BlockAckRequestTest
    Dot11CFEndTest
    Dot11CFEndACKTest
    Dot11DataTest
    Dot11DeauthenticationTest
    Dot11DisassocTest
    Dot11Test
    Dot11ProbeRequestTest
    Dot11ProbeResponseTest
    Dot11PSPollTest
    Dot11ReassocRequestTest
    Dot11ReassocResponseTest
    Dot11RTSTest
    Dot1QTest
    EthernetTest
    HWAddressTest
    ICMPTest
    ICMPv6Test
    IPTest
    IPReassemblerTest
    IPAddressTest
    IPSecTest
    IPv6Test
    IPv6AddressTest
    LLCTest
    MatchesResponseTest
    NetworkInterfaceTest
    OfflinePacketFilterTest
    PDUTest
    PPITest
    PPPoETest
    RadioTapTest
    RC4EAPOLTest
    RSNEAPOLTest
    SLLTest
    SNAPTest
    STPTest
    TCPTest
    TCPStreamTest
    UDPTest
    UtilsTest
    WEPDecryptTest
    WPA2DecryptTest
)

# Test executables

ADD_EXECUTABLE(AddressRangeTest EXCLUDE_FROM_ALL address_range.cpp)
ADD_EXECUTABLE(AllocatorsTest EXCLUDE_FROM_ALL allocators.cpp)
ADD_EXECUTABLE(ArpTest EXCLUDE_FROM_ALL arp.cpp)
ADD_EXECUTABLE(DHCPTest EXCLUDE_FROM_ALL dhcp.cpp)
ADD_EXECUTABLE(DHCPv6Test EXCLUDE_FROM_ALL dhcpv6.cpp)
ADD_EXECUTABLE(DNSTest EXCLUDE_FROM_ALL dns.cpp)
ADD_EXECUTABLE(Dot1QTest EXCLUDE_FROM_ALL dot1q.cpp)
ADD_EXECUTABLE(EthernetTest EXCLUDE_FROM_ALL ethernetII.cpp)
ADD_EXECUTABLE(HWAddressTest EXCLUDE_FROM_ALL hwaddress.cpp)
ADD_EXECUTABLE(ICMPTest EXCLUDE_FROM_ALL icmp.cpp)
ADD_EXECUTABLE(ICMPv6Test EXCLUDE_FROM_ALL icmpv6.cpp)
ADD_EXECUTABLE(IPTest EXCLUDE_FROM_ALL ip.cpp)
ADD_EXECUTABLE(IPReassemblerTest EXCLUDE_FROM_ALL ip_reassembler.cpp)
ADD_EXECUTABLE(IPAddressTest EXCLUDE_FROM_ALL ipaddress.cpp)
ADD_EXECUTABLE(IPSecTest EXCLUDE_FROM_ALL ipsec.cpp)
ADD_EXECUTABLE(IPv6Test EXCLUDE_FROM_ALL ipv6.cpp)
ADD_EXECUTABLE(IPv6AddressTest EXCLUDE_FROM_ALL ipv6address.cpp)
ADD_EXECUTABLE(LLCTest EXCLUDE_FROM_ALL llc.cpp)
ADD_EXECUTABLE(MatchesResponseTest EXCLUDE_FROM_ALL matches_response.cpp)
ADD_EXECUTABLE(NetworkInterfaceTest EXCLUDE_FROM_ALL network_interface.cpp)
ADD_EXECUTABLE(OfflinePacketFilterTest EXCLUDE_FROM_ALL offline_packet_filter.cpp)
ADD_EXECUTABLE(PDUTest EXCLUDE_FROM_ALL pdu.cpp)
ADD_EXECUTABLE(PPITest EXCLUDE_FROM_ALL ppi.cpp)
ADD_EXECUTABLE(PPPoETest EXCLUDE_FROM_ALL pppoe.cpp)
ADD_EXECUTABLE(RadioTapTest EXCLUDE_FROM_ALL radiotap.cpp)
ADD_EXECUTABLE(RC4EAPOLTest EXCLUDE_FROM_ALL rc4eapol.cpp)
ADD_EXECUTABLE(RSNEAPOLTest EXCLUDE_FROM_ALL rsn_eapol.cpp)
ADD_EXECUTABLE(SLLTest EXCLUDE_FROM_ALL sll.cpp)
ADD_EXECUTABLE(SNAPTest EXCLUDE_FROM_ALL snap.cpp)
ADD_EXECUTABLE(STPTest EXCLUDE_FROM_ALL stp.cpp)
ADD_EXECUTABLE(TCPTest EXCLUDE_FROM_ALL tcp.cpp)
ADD_EXECUTABLE(TCPStreamTest EXCLUDE_FROM_ALL tcp_stream.cpp)
ADD_EXECUTABLE(UDPTest EXCLUDE_FROM_ALL udp.cpp)
ADD_EXECUTABLE(UtilsTest EXCLUDE_FROM_ALL utils.cpp)
ADD_EXECUTABLE(WEPDecryptTest EXCLUDE_FROM_ALL wep_decrypt.cpp)
ADD_EXECUTABLE(WPA2DecryptTest EXCLUDE_FROM_ALL wpa2_decrypt.cpp)

# Dot11 tests executables

ADD_EXECUTABLE(Dot11AckTest EXCLUDE_FROM_ALL dot11/ack.cpp)
ADD_EXECUTABLE(Dot11AssocRequestTest EXCLUDE_FROM_ALL dot11/assoc_request.cpp)
ADD_EXECUTABLE(Dot11AssocResponseTest EXCLUDE_FROM_ALL dot11/assoc_response.cpp)
ADD_EXECUTABLE(Dot11AuthenticationTest EXCLUDE_FROM_ALL dot11/authentication.cpp)
ADD_EXECUTABLE(Dot11BeaconTest EXCLUDE_FROM_ALL dot11/beacon.cpp)
ADD_EXECUTABLE(Dot11BlockAckRequestTest EXCLUDE_FROM_ALL dot11/block_ack_request.cpp)
ADD_EXECUTABLE(Dot11CFEndTest EXCLUDE_FROM_ALL dot11/cfend.cpp)
ADD_EXECUTABLE(Dot11CFEndACKTest EXCLUDE_FROM_ALL dot11/cfendack.cpp)
ADD_EXECUTABLE(Dot11DataTest EXCLUDE_FROM_ALL dot11/data.cpp)
ADD_EXECUTABLE(Dot11DeauthenticationTest EXCLUDE_FROM_ALL dot11/deauthentication.cpp)
ADD_EXECUTABLE(Dot11DisassocTest EXCLUDE_FROM_ALL dot11/disassoc.cpp)
ADD_EXECUTABLE(Dot11Test EXCLUDE_FROM_ALL dot11/dot11.cpp)
ADD_EXECUTABLE(Dot11ProbeRequestTest EXCLUDE_FROM_ALL dot11/probe_request.cpp)
ADD_EXECUTABLE(Dot11ProbeResponseTest EXCLUDE_FROM_ALL dot11/probe_response.cpp)
ADD_EXECUTABLE(Dot11PSPollTest EXCLUDE_FROM_ALL dot11/pspoll.cpp)
ADD_EXECUTABLE(Dot11ReassocRequestTest EXCLUDE_FROM_ALL dot11/reassoc_request.cpp)
ADD_EXECUTABLE(Dot11ReassocResponseTest EXCLUDE_FROM_ALL dot11/reassoc_response.cpp)
ADD_EXECUTABLE(Dot11RTSTest EXCLUDE_FROM_ALL dot11/rts.cpp)

# Tests

ADD_TEST(AddressRange AddressRangeTest)
ADD_TEST(Allocators AllocatorsTest)
ADD_TEST(Arp ArpTest)
ADD_TEST(DHCP DHCPTest)
ADD_TEST(DHCPv6 DHCPv6Test)
ADD_TEST(DNS DNSTest)
ADD_TEST(Dot11Ack Dot11AckTest)
ADD_TEST(Dot11AssocRequest Dot11AssocRequestTest)
ADD_TEST(Dot11AssocResponse Dot11AssocResponseTest)
ADD_TEST(Dot11Authentication Dot11AuthenticationTest)
ADD_TEST(Dot11Beacon Dot11BeaconTest)
ADD_TEST(Dot11BlockAckRequest Dot11BlockAckRequestTest)
ADD_TEST(Dot11CFEnd Dot11CFEndTest)
ADD_TEST(Dot11CFEndACK Dot11CFEndACKTest)
ADD_TEST(Dot11Data Dot11DataTest)
ADD_TEST(Dot11Deauthentication Dot11DeauthenticationTest)
ADD_TEST(Dot11Disassoc Dot11DisassocTest)
ADD_TEST(Dot11 Dot11Test)
ADD_TEST(Dot11ProbeRequest Dot11ProbeRequestTest)
ADD_TEST(Dot11ProbeResponse Dot11ProbeResponseTest)
ADD_TEST(Dot11PSPoll Dot11PSPollTest)
ADD_TEST(Dot11ReassocRequest Dot11ReassocRequestTest)
ADD_TEST(Dot11ReassocResponse Dot11ReassocResponseTest)
ADD_TEST(Dot11RTS Dot11RTSTest)
ADD_TEST(Dot1Q Dot1QTest)
ADD_TEST(Ethernet EthernetTest)
ADD_TEST(HWAddress HWAddressTest)
ADD_TEST(ICMP ICMPTest)
ADD_TEST(ICMPv6 ICMPv6Test)
ADD_TEST(IP IPTest)
ADD_TEST(IPReassembler IPReassemblerTest)
ADD_TEST(IPAddress IPAddressTest)
ADD_TEST(IPSec IPSecTest)
ADD_TEST(IPv6 IPv6Test)
ADD_TEST(IPv6Address IPv6AddressTest)
ADD_TEST(LLC LLCTest)
ADD_TEST(MatchesResponse MatchesResponseTest)
ADD_TEST(NetworkInterface NetworkInterfaceTest)
ADD_TEST(OfflinePacketFilter OfflinePacketFilterTest)
ADD_TEST(PDU PDUTest)
ADD_TEST(PPI PPITest)
ADD_TEST(PPPoE PPPoETest)
ADD_TEST(RadioTap RadioTapTest)
ADD_TEST(RC4EAPOL RC4EAPOLTest)
ADD_TEST(RSNEAPOL RSNEAPOLTest)
ADD_TEST(SLL SLLTest)
ADD_TEST(SNAP SNAPTest)
ADD_TEST(STP STPTest)
ADD_TEST(TCP TCPTest)
ADD_TEST(TCPStream TCPStreamTest)
ADD_TEST(UDP UDPTest)
ADD_TEST(Utils UtilsTest)
ADD_TEST(WEPDecrypt WEPDecryptTest)
ADD_TEST(WPA2Decrypt WPA2DecryptTest)

