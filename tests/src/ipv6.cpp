#include <gtest/gtest.h>
#include <cstring>
#include <string>
#include <stdint.h>
#include "ipv6.h"
#include "tcp.h"
#include "udp.h"
#include "icmp.h"
#include "ipv6_address.h"
#include "utils.h"

using namespace std;
using namespace Tins;

class IPv6Test : public testing::Test {
public:
    static const uint8_t expected_packet[];
    
    void test_equals(const IPv6 &ip1, const IPv6 &ip2);
};

const uint8_t IPv6Test::expected_packet[] = {
    'i', '\xa8', '\'', '4', '\x00', '(', '\x06', '@', '\x00', '\x00', 
    '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', 
    '\x00', '\x00', '\x00', '\x00', '\x01', '\x00', '\x00', '\x00', '\x00', 
    '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', 
    '\x00', '\x00', '\x01', '\xc6', '\x8c', '\x00', 'P', 'h', 'H', '\x03', 
    '\x0c', '\x00', '\x00', '\x00', '\x00', '\xa0', '\x02', '\x7f', '\xf0', 
    '\x00', '0', '\x00', '\x00', '\x02', '\x04', '?', '\xf8', '\x04', 
    '\x02', '\x08', '\n', '\x00', '\x84', '\xa3', '\x9c', '\x00', '\x00', 
    '\x00', '\x00', '\x01', '\x03', '\x03', '\x07'
};

TEST_F(IPv6Test, Constructor) {
    IPv6 ipv6("::1:2:3", "f0aa:beef::1");
    EXPECT_EQ(ipv6.version(), 6);
    EXPECT_EQ(ipv6.traffic_class(), 0);
    EXPECT_EQ(ipv6.flow_label(), 0);
    EXPECT_EQ(ipv6.payload_length(), 0);
    EXPECT_EQ(ipv6.next_header(), 0);
    EXPECT_EQ(ipv6.hop_limit(), 0);
    EXPECT_EQ(ipv6.dst_addr(), "::1:2:3");
    EXPECT_EQ(ipv6.src_addr(), "f0aa:beef::1");
}

TEST_F(IPv6Test, ConstructorFromBuffer) {
    IPv6 ipv6(expected_packet, sizeof(expected_packet));
    EXPECT_EQ(ipv6.version(), 6);
    EXPECT_EQ(ipv6.traffic_class(), 0x9a);
    EXPECT_EQ(ipv6.flow_label(), 0x82734);
    EXPECT_EQ(ipv6.payload_length(), 40);
    EXPECT_EQ(ipv6.next_header(), 6);
    EXPECT_EQ(ipv6.hop_limit(), 64);
    EXPECT_EQ(ipv6.dst_addr(), "::1");
    EXPECT_EQ(ipv6.src_addr(), "::1");
    ASSERT_TRUE(ipv6.inner_pdu());
    TCP *tcp = ipv6.find_pdu<TCP>();
    ASSERT_TRUE(tcp);
    EXPECT_EQ(tcp->sport(), 50828);
    EXPECT_EQ(tcp->dport(), 80);
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
    EXPECT_EQ(ipv6.flow_label(), 0x918d7);
}

TEST_F(IPv6Test, PayloadLength) {
    IPv6 ipv6;
    ipv6.payload_length(0xaf71);
    EXPECT_EQ(ipv6.payload_length(), 0xaf71);
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

