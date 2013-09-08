#include <gtest/gtest.h>
#include <cstring>
#include <string>
#include <algorithm>
#include <sstream>
#include <stdint.h>
#include "ipv6_address.h"
#include "utils.h"

using namespace Tins;


const uint8_t empty_addr[IPv6Address::address_size] = { 0 };

void test_to_string(const std::string &str) {
    EXPECT_EQ(str, IPv6Address(str).to_string());
}

TEST(IPv6AddressTest, DefaultConstructor) {
    IPv6Address addr;
    EXPECT_TRUE(std::equal(addr.begin(), addr.end(), empty_addr));
}

TEST(IPv6AddressTest, ConstructorFromString1) {
    IPv6Address addr("2001:db8:85a3:8d3:1319:8a2e:370:7348");
    const uint8_t some_addr[IPv6Address::address_size] = {
        0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0xd3, 0x13, 0x19, 
        0x8a, 0x2e, 0x03, 0x70, 0x73, 0x48
    };
    EXPECT_TRUE(std::equal(addr.begin(), addr.end(), some_addr));
}

TEST(IPv6AddressTest, ConstructorFromString2) {
    IPv6Address addr("2001:db8:85a3::1319:8a2e:370:7348");
    const uint16_t some_addr[IPv6Address::address_size] = {
        0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x13, 0x19, 
        0x8a, 0x2e, 0x03, 0x70, 0x73, 0x48
    };
    EXPECT_TRUE(std::equal(addr.begin(), addr.end(), some_addr));
}

TEST(IPv6AddressTest, ConstructorFromString3) {
    IPv6Address addr("::1");
    const uint16_t some_addr[IPv6Address::address_size] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
    };
    EXPECT_TRUE(std::equal(addr.begin(), addr.end(), some_addr));
}

TEST(IPv6AddressTest, ToString) {
    test_to_string("2001:db8:85a3:8d3:1319:8a2e:370:7348");
    test_to_string("2001:db8:85a3:8d3:1319:8a2e::");
    test_to_string("1:db8:85a3:8d3:1319:8a2e:370:7348");
    test_to_string("::85a3:8d3:1319:8a2e:370:7348");
    test_to_string("::1:2:3");
}

TEST(IPv6AddressTest, EqualOperator) {
    EXPECT_EQ(IPv6Address("17f8::1"), IPv6Address("17f8:0::0:1"));
    EXPECT_EQ(IPv6Address("::1"), IPv6Address("::1"));
    EXPECT_EQ(IPv6Address("1::"), IPv6Address("1::"));
}

TEST(IPv6AddressTest, DistinctOperator) {
    EXPECT_NE(IPv6Address("17f8::12"), IPv6Address("17f8:0::1:12"));
    EXPECT_NE(IPv6Address("::1"), IPv6Address("::2"));
    EXPECT_NE(IPv6Address("4::"), IPv6Address("5::"));
}

TEST(IPv6AddressTest, LessThanOperator) {
    EXPECT_LT(IPv6Address("17f8::1"), IPv6Address("17f8:0::0:5"));
    EXPECT_LT(IPv6Address("::1"), IPv6Address("::5"));
    EXPECT_LT(IPv6Address("1::"), IPv6Address("2::"));
}

TEST(IPv6AddressTest, OutputOperator) {
    std::ostringstream oss;
    oss << IPv6Address("17f8::1");
    EXPECT_EQ("17f8::1", oss.str());
}

TEST(IPv6AddressTest, Copy) {
    IPv6Address addr1("17f8::1");
    IPv6Address addr2;
    addr1.copy(addr2.begin());
    EXPECT_EQ(addr1, addr2);
}

TEST(IPv6AddressTest, IsLoopback) {
    EXPECT_TRUE(IPv6Address("::1").is_loopback());
    EXPECT_FALSE(IPv6Address("::2").is_loopback());
    EXPECT_FALSE(IPv6Address("ffff::2").is_loopback());
}

TEST(IPv6AddressTest, IsMulticast) {
    EXPECT_TRUE(IPv6Address("ff00::1").is_multicast());
    EXPECT_TRUE(IPv6Address("ff02::1").is_multicast());
    EXPECT_TRUE(IPv6Address("ffff::ffff").is_multicast());
    EXPECT_FALSE(IPv6Address("f000::").is_multicast());
    EXPECT_FALSE(IPv6Address("feaa::dead").is_multicast());
}

