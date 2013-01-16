#include <gtest/gtest.h>
#include <cstring>
#include <string>
#include <stdint.h>
#include "dhcpv6.h"

using namespace Tins;

class DHCPv6Test : public testing::Test {
public:
    static const uint8_t expected_packet[];

    void test_equals(const DHCPv6 &dhcp1, const DHCPv6 &dhcp2);
};

const uint8_t DHCPv6Test::expected_packet[] = {
    '\x01', '\xe8', '(', '\xb9', '\x00', '\x01', '\x00', '\n', '\x00', 
    '\x03', '\x00', '\x01', '\x00', '\x01', '\x02', '\x03', '\x04', 
    '\x05', '\x00', '\x03', '\x00', '\x0c', '\x00', '\x00', '\x00', 
    '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', 
    '\x00', '\x00', '\x08', '\x00', '\x02', '\x00', '\x00', '\x00',
    '\x06', '\x00', '\x02', '\x00', '\x03'
};

TEST_F(DHCPv6Test, DefaultConstructor) {
    DHCPv6 dhcp;
    EXPECT_EQ(0, dhcp.msg_type());
    EXPECT_EQ(0, dhcp.hop_count());
    EXPECT_EQ(0, dhcp.transaction_id());
}

TEST_F(DHCPv6Test, ConstructorFromBuffer) {
    DHCPv6 dhcp(expected_packet, sizeof(expected_packet));
    EXPECT_EQ(1, dhcp.msg_type());
    EXPECT_EQ(0xe828b9, dhcp.transaction_id());
    EXPECT_TRUE(dhcp.search_option(1));
    EXPECT_TRUE(dhcp.search_option(3));
    EXPECT_TRUE(dhcp.search_option(6));
    EXPECT_TRUE(dhcp.search_option(8));
    EXPECT_FALSE(dhcp.search_option(2));
}

TEST_F(DHCPv6Test, Serialize) {
    DHCPv6 dhcp(expected_packet, sizeof(expected_packet));
    DHCPv6::serialization_type buffer = dhcp.serialize();
    ASSERT_EQ(sizeof(expected_packet), buffer.size());
    EXPECT_EQ(
        DHCPv6::serialization_type(expected_packet, expected_packet + sizeof(expected_packet)),
        buffer
    );
}

TEST_F(DHCPv6Test, MessageType) {
    DHCPv6 dhcp;
    dhcp.msg_type(0x8a);
    EXPECT_EQ(0x8a, dhcp.msg_type());
}

TEST_F(DHCPv6Test, HopCount) {
    DHCPv6 dhcp;
    dhcp.hop_count(0x8a);
    EXPECT_EQ(0x8a, dhcp.hop_count());
}

TEST_F(DHCPv6Test, TransactionId) {
    DHCPv6 dhcp;
    dhcp.transaction_id(0x8af2ad);
    EXPECT_EQ(0x8af2ad, dhcp.transaction_id());
}
