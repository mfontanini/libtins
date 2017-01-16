#include <gtest/gtest.h>
#include <cstring>
#include <string>
#include <stdint.h>
#include "ipv6.h"
#include "tcp.h"
#include "udp.h"
#include "icmp.h"
#include "icmpv6.h"
#include "rawpdu.h"
#include "ethernetII.h"
#include "ipv6_address.h"
#include "utils.h"

using namespace std;
using namespace Tins;

#ifdef _WIN32
    #define TINS_DEFAULT_TEST_IP "::"
#else 
    #define TINS_DEFAULT_TEST_IP "::1"
#endif

class IPv6Test : public testing::Test {
public:
    static const uint8_t expected_packet1[], expected_packet2[], 
                         hop_by_hop_options[], broken1[],
                         fcs_suffix[];
    
    void test_equals(IPv6& ip1, IPv6& ip2);
};

const uint8_t IPv6Test::expected_packet1[] = {
    105, 168, 39, 52, 0, 40, 6, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 198, 140, 
    0, 80, 104, 72, 3, 12, 0, 0, 0, 0, 160, 2, 127, 240, 183, 120, 0, 0, 2, 
    4, 63, 248, 4, 2, 8, 10, 0, 132, 163, 156, 0, 0, 0, 0, 1, 3, 3, 7
};

const uint8_t IPv6Test::expected_packet2[] = {
    96, 0, 0, 0, 0, 36, 0, 1, 254, 128, 0, 0, 0, 0, 0, 0, 2, 208, 9, 255, 
    254, 227, 232, 222, 255, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    22, 58, 0, 5, 2, 0, 0, 1, 0, 143, 0, 116, 254, 0, 0, 0, 1, 4, 0, 0, 
    0, 255, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 255, 152, 6, 225
};

const uint8_t IPv6Test::hop_by_hop_options[] = { 
    0, 1, 1, 0, 0, 2, 0, 1, 1, 0, 0, 1, 134, 221, 96, 0, 0, 0, 0, 180, 0, 255, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 58, 1, 
    0, 0, 0, 0, 0, 0, 5, 2, 0, 0, 0, 0, 0, 0, 143, 0, 27, 180, 0, 0, 0, 1, 1, 2, 0, 8, 255, 
    2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 255, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 255, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 255, 2, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 1, 255, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 255, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 255, 0, 0, 9, 
    222, 173, 190, 239, 190, 173, 254, 237
};

const uint8_t IPv6Test::broken1[] = { 
    51, 51, 0, 0, 0, 251, 96, 3, 8, 165, 51, 186, 134, 221, 96, 14, 233, 9, 0, 11, 44, 255,
    254, 128, 0, 0, 0, 0, 0, 0, 98, 3, 8, 255, 254, 165, 51, 186, 255, 2, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 251, 17, 0, 11, 80, 53, 98, 2, 81, 72, 50, 10
};

const uint8_t IPv6Test::fcs_suffix[] = {
    0x33, 0x33, 0xff, 0x01, 0x31, 0x3e, 0x64, 0x3f, 0x5f, 0x01, 0x31, 0x3e, 0x86, 0xdd, 0x60, 0x00,
    0x00, 0x00, 0x00, 0x18, 0x3a, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x01, 0xff, 0x01, 0x31, 0x3e, 0x87, 0x00, 0x55, 0x69, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x80,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x66, 0x3f, 0x5f, 0xff, 0xfe, 0x01, 0x31, 0x3e, 0x23, 0x0c,
    0x57, 0xb7
};

void IPv6Test::test_equals(IPv6& ip1, IPv6& ip2) {
    EXPECT_EQ(ip1.version(), ip2.version());
    EXPECT_EQ(ip1.traffic_class(), ip2.traffic_class());
    EXPECT_EQ(ip1.flow_label(), ip2.flow_label());
    EXPECT_EQ(ip1.payload_length(), ip2.payload_length());
    EXPECT_EQ(ip1.next_header(), ip2.next_header());
    EXPECT_EQ(ip1.hop_limit(), ip2.hop_limit());
    EXPECT_EQ(ip1.dst_addr(), ip2.dst_addr());
    EXPECT_EQ(ip1.src_addr(), ip2.src_addr());
    
    EXPECT_EQ(ip1.search_header(IPv6::HOP_BY_HOP) != NULL, 
                ip2.search_header(IPv6::HOP_BY_HOP) != NULL);
    const IPv6::ext_header* header1 = ip1.search_header(IPv6::HOP_BY_HOP),
                                    *header2 = ip2.search_header(IPv6::HOP_BY_HOP);
    if(header1 && header2) {
        EXPECT_EQ(header1->data_size(), header2->data_size());
    }
    
    EXPECT_EQ(ip1.inner_pdu() != NULL, ip2.inner_pdu() != NULL);
    
    const ICMPv6* icmp1 = ip1.find_pdu<ICMPv6>(), *icmp2 = ip2.find_pdu<ICMPv6>();
    ASSERT_EQ(icmp1 != NULL, icmp2 != NULL);
    
    if(icmp1 && icmp2) {
        EXPECT_EQ(icmp1->checksum(), icmp2->checksum());
    }
}

TEST_F(IPv6Test, Constructor) {
    IPv6 ipv6("::1:2:3", "f0aa:beef::1");
    EXPECT_EQ(ipv6.version(), 6);
    EXPECT_EQ(ipv6.traffic_class(), 0);
    EXPECT_EQ(ipv6.flow_label(), 0U);
    EXPECT_EQ(ipv6.payload_length(), 0);
    EXPECT_EQ(ipv6.next_header(), 0);
    EXPECT_EQ(ipv6.hop_limit(), 0);
    EXPECT_EQ(ipv6.dst_addr(), "::1:2:3");
    EXPECT_EQ(ipv6.src_addr(), "f0aa:beef::1");
}

TEST_F(IPv6Test, ConstructorFromBuffer) {
    IPv6 ipv6(expected_packet1, sizeof(expected_packet1));
    EXPECT_EQ(ipv6.version(), 6);
    EXPECT_EQ(ipv6.traffic_class(), 0x9a);
    EXPECT_EQ(ipv6.flow_label(), 0x82734U);
    EXPECT_EQ(ipv6.payload_length(), 40);
    EXPECT_EQ(ipv6.next_header(), 6);
    EXPECT_EQ(ipv6.hop_limit(), 64);
    EXPECT_EQ(ipv6.dst_addr(), "::1");
    EXPECT_EQ(ipv6.src_addr(), "::1");
    ASSERT_TRUE(ipv6.inner_pdu() != NULL);
    TCP* tcp = ipv6.find_pdu<TCP>();
    ASSERT_TRUE(tcp != NULL);
    EXPECT_EQ(tcp->sport(), 50828);
    EXPECT_EQ(tcp->dport(), 80);
}

// This one has a hop-by-hop ext header
TEST_F(IPv6Test, ConstructorFromBuffer2) {
    IPv6 ipv6(expected_packet2, sizeof(expected_packet2));
    EXPECT_EQ(ipv6.version(), 6);
    EXPECT_EQ(ipv6.traffic_class(), 0);
    EXPECT_EQ(ipv6.flow_label(), 0U);
    EXPECT_EQ(ipv6.payload_length(), 36);
    EXPECT_EQ(ipv6.next_header(), IPv6::HOP_BY_HOP);
    EXPECT_EQ(ipv6.hop_limit(), 1);
    EXPECT_EQ(ipv6.dst_addr(), "ff02::16");
    EXPECT_EQ(ipv6.src_addr(), "fe80::2d0:9ff:fee3:e8de");
    
    ICMPv6* pdu = ipv6.find_pdu<ICMPv6>();
    ASSERT_TRUE(pdu != NULL);
    EXPECT_EQ(pdu->type(), 143);
    EXPECT_EQ(pdu->code(), 0);
    EXPECT_EQ(pdu->checksum(), 0x74fe);
    EXPECT_EQ(pdu->checksum(), 0x74fe);
    
    const IPv6::ext_header* header = ipv6.search_header(IPv6::HOP_BY_HOP);
    ASSERT_TRUE(header != NULL);
    EXPECT_EQ(header->data_size(), 6U);
}

TEST_F(IPv6Test, ConstructorFromBuffer_MLD2_Packet) {
    EthernetII eth(hop_by_hop_options, sizeof(hop_by_hop_options));

    PDU::serialization_type buffer = eth.serialize();
    EXPECT_EQ(
        PDU::serialization_type(
            hop_by_hop_options, 
            hop_by_hop_options + sizeof(hop_by_hop_options)
        ),
        buffer
    );
}

TEST_F(IPv6Test, Serialize) {
    IPv6 ip1(expected_packet1, sizeof(expected_packet1));
    IPv6::serialization_type buffer = ip1.serialize();
    ASSERT_EQ(buffer.size(), sizeof(expected_packet1));
    EXPECT_EQ(
        IPv6::serialization_type(expected_packet1, expected_packet1 + sizeof(expected_packet1)),
        buffer
    );
    IPv6 ip2(&buffer[0], (uint32_t)buffer.size());
    test_equals(ip1, ip2);
}

TEST_F(IPv6Test, Broken1) {
    EthernetII pkt(broken1, sizeof(broken1));
    EXPECT_EQ(
        PDU::serialization_type(broken1, broken1 + sizeof(broken1)),
        pkt.serialize()
    );
}

TEST_F(IPv6Test, FCSSuffix) {
    EthernetII pkt(fcs_suffix, sizeof(fcs_suffix));
    EXPECT_EQ(pkt.rfind_pdu<IPv6>().payload_length(), 24u);
    EXPECT_EQ(pkt.rfind_pdu<ICMPv6>().size(), 24u);
    EXPECT_EQ(
        PDU::serialization_type(fcs_suffix, fcs_suffix + pkt.size()),
        pkt.serialize()
    );
}

TEST_F(IPv6Test, Version) {
    IPv6 ipv6;
    ipv6.version(3);
    EXPECT_EQ(ipv6.version(), 3);
}

TEST_F(IPv6Test, TrafficClass) {
    IPv6 ipv6;
    ipv6.traffic_class(0x7a);
    EXPECT_EQ(ipv6.traffic_class(), 0x7a);
}

TEST_F(IPv6Test, FlowLabel) {
    IPv6 ipv6;
    ipv6.flow_label(0x918d7);
    EXPECT_EQ(ipv6.flow_label(), 0x918d7U);
}

TEST_F(IPv6Test, PayloadLength) {
    IPv6 ipv6;
    ipv6.payload_length(0xaf71);
    EXPECT_EQ(ipv6.payload_length(), 0xaf71U);
}

TEST_F(IPv6Test, NextHeader) {
    IPv6 ipv6;
    ipv6.next_header(0x7a);
    EXPECT_EQ(ipv6.next_header(), 0x7a);
}

TEST_F(IPv6Test, HopLimit) {
    IPv6 ipv6;
    ipv6.hop_limit(0x7a);
    EXPECT_EQ(ipv6.hop_limit(), 0x7a);
}

TEST_F(IPv6Test, SourceAddress) {
    IPv6 ipv6;
    ipv6.src_addr("99af:1293::1");
    EXPECT_EQ(ipv6.src_addr(), "99af:1293::1");
}

TEST_F(IPv6Test, DestinationAddress) {
    IPv6 ipv6;
    ipv6.dst_addr("99af:1293::1");
    EXPECT_EQ(ipv6.dst_addr(), "99af:1293::1");
}

// Make sure that a big payload is not considered ICMP extensions
TEST_F(IPv6Test, BigEncapsulatedPacketIsNotConsideredToHaveExtensions) {
    IPv6 encapsulated = IPv6(TINS_DEFAULT_TEST_IP) / UDP(99, 12) / RawPDU(std::string(250, 'A'));
    EthernetII pkt = EthernetII() / IPv6() / ICMPv6(ICMPv6::TIME_EXCEEDED) / encapsulated;

    PDU::serialization_type buffer = pkt.serialize();
    EthernetII serialized(&buffer[0], buffer.size());
    ASSERT_EQ(encapsulated.size(), serialized.rfind_pdu<RawPDU>().payload().size());
    ASSERT_TRUE(serialized.rfind_pdu<ICMPv6>().extensions().extensions().empty());
}

// Use a large buffer. This wil set the length field
TEST_F(IPv6Test, SerializePacketHavingICMPExtensionsWithLengthAndLotsOfPayload) {
    IPv6 encapsulated = IPv6(TINS_DEFAULT_TEST_IP) / UDP(99, 12) / RawPDU(std::string(250, 'A'));
    EthernetII pkt = EthernetII() / IPv6() / ICMPv6(ICMPv6::TIME_EXCEEDED) / encapsulated;
    const uint8_t payload[] = { 24, 150, 1, 1 }; 
    ICMPExtension extension(1, 1);
    ICMPExtension::payload_type ext_payload(payload, payload + sizeof(payload));
    extension.payload(ext_payload);
    pkt.rfind_pdu<ICMPv6>().extensions().add_extension(extension);

    PDU::serialization_type buffer = pkt.serialize();
    EthernetII serialized(&buffer[0], buffer.size());
    ASSERT_EQ(1UL, serialized.rfind_pdu<ICMPv6>().extensions().extensions().size());
    EXPECT_EQ(ext_payload, serialized.rfind_pdu<ICMPv6>().extensions().extensions().begin()->payload());
}

// Use a short buffer and set the length field
TEST_F(IPv6Test, SerializePacketHavingICMPExtensionsWithLengthAndShortPayload) {
    IPv6 encapsulated = IPv6(TINS_DEFAULT_TEST_IP) / UDP(99, 12) / RawPDU(std::string(40, 'A'));
    EthernetII pkt = EthernetII() / IPv6() / ICMPv6(ICMPv6::TIME_EXCEEDED) / encapsulated;
    const uint8_t payload[] = { 24, 150, 1, 1 }; 
    ICMPExtension extension(1, 1);
    ICMPExtension::payload_type ext_payload(payload, payload + sizeof(payload));
    extension.payload(ext_payload);
    pkt.rfind_pdu<ICMPv6>().extensions().add_extension(extension);
    pkt.rfind_pdu<ICMPv6>().use_length_field(true);

    PDU::serialization_type buffer = pkt.serialize();
    EthernetII serialized(&buffer[0], buffer.size());
    ASSERT_EQ(1UL, serialized.rfind_pdu<ICMPv6>().extensions().extensions().size());
    EXPECT_EQ(ext_payload, serialized.rfind_pdu<ICMPv6>().extensions().extensions().begin()->payload());
}

// Use a short buffer and don't set the length field
TEST_F(IPv6Test, SerializePacketHavingICMPExtensionsWithoutLengthAndShortPayload) {
    IPv6 encapsulated = IPv6(TINS_DEFAULT_TEST_IP) / UDP(99, 12) / RawPDU(std::string(40, 'A'));
    EthernetII pkt = EthernetII() / IPv6() / ICMPv6(ICMPv6::TIME_EXCEEDED) / encapsulated;
    const uint8_t payload[] = { 24, 150, 1, 1 }; 
    ICMPExtension extension(1, 1);
    ICMPExtension::payload_type ext_payload(payload, payload + sizeof(payload));
    extension.payload(ext_payload);
    pkt.rfind_pdu<ICMPv6>().extensions().add_extension(extension);
    pkt.rfind_pdu<ICMPv6>().use_length_field(false);

    PDU::serialization_type buffer = pkt.serialize();
    EthernetII serialized(&buffer[0], buffer.size());
    ASSERT_EQ(1UL, serialized.rfind_pdu<ICMPv6>().extensions().extensions().size());
    EXPECT_EQ(ext_payload, serialized.rfind_pdu<ICMPv6>().extensions().extensions().begin()->payload());
}

TEST_F(IPv6Test, MDLv1Request) {
    const uint8_t mldv1[] = {
        51, 51, 0, 0, 0, 1, 100, 112, 2, 226, 169, 250, 134, 221, 96, 0, 0, 0, 0, 32, 0, 1, 254,
        128, 0, 0, 0, 0, 0, 0, 102, 112, 2, 255, 254, 226, 169, 250, 255, 2, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 1, 58, 0, 5, 2, 0, 0, 0, 0, 130, 0, 70, 203, 39, 16, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    EthernetII pkt(mldv1, sizeof(mldv1));
    EXPECT_EQ(
        PDU::serialization_type(mldv1, mldv1 + sizeof(mldv1)),
        pkt.serialize()
    );
}

