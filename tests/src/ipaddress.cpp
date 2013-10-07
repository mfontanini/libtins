#include <gtest/gtest.h>
#include <cstring>
#include <string>
#include <sstream>
#include <stdint.h>
#include "ip_address.h"
#include "utils.h"

using namespace Tins;

std::string ip_string("192.168.0.225");

TEST(IPAddressTest, Constructor) {
    IPv4Address addr1(ip_string);
    IPv4Address addr2(ip_string);
    EXPECT_EQ(addr2, addr1);
    EXPECT_EQ(addr1.to_string(), ip_string);
    EXPECT_EQ(addr2.to_string(), ip_string);
    EXPECT_NE(addr1, "192.168.0.254");
}

TEST(IPAddressTest, CopyAssignmentOperator) {
    IPv4Address addr1(ip_string);
    uint32_t as_int = addr1;
    IPv4Address addr2;
    addr2 = IPv4Address(as_int);
    EXPECT_EQ(addr1, addr2);
    uint32_t as_int2 = addr2;
    EXPECT_EQ(as_int2, as_int);
}

TEST(IPAddressTest, OutputOperator) {
    IPv4Address addr(ip_string);
    std::ostringstream oss;
    oss << addr;
    EXPECT_EQ(oss.str(), ip_string);
}

TEST(IPAddressTest, EqualityOperator) {
    IPv4Address addr1(ip_string), addr2(ip_string);
    EXPECT_EQ(addr1, addr2);
    EXPECT_NE(addr1, "127.0.0.1");
}

TEST(IPAddressTest, LessThanOperator) {
    IPv4Address addr1(ip_string), addr2(ip_string);
    EXPECT_FALSE(addr1 < addr2);
    EXPECT_LT(addr1, "192.168.1.2");
    EXPECT_LT(addr1, "192.168.0.226");
    EXPECT_LT(addr1, "193.0.0.0");
}

TEST(IPAddressTest, IsPrivate) {
    EXPECT_TRUE(IPv4Address("192.168.0.1").is_private());
    EXPECT_TRUE(IPv4Address("192.168.133.7").is_private());
    EXPECT_TRUE(IPv4Address("192.168.255.254").is_private());
    EXPECT_FALSE(IPv4Address("192.169.0.1").is_private());
    EXPECT_FALSE(IPv4Address("192.167.255.254").is_private());
    
    EXPECT_TRUE(IPv4Address("10.0.0.1").is_private());
    EXPECT_TRUE(IPv4Address("10.5.1.2").is_private());
    EXPECT_TRUE(IPv4Address("10.255.255.254").is_private());
    EXPECT_FALSE(IPv4Address("11.0.0.1").is_private());
    EXPECT_FALSE(IPv4Address("9.255.255.254").is_private());
    
    EXPECT_TRUE(IPv4Address("172.16.0.1").is_private());
    EXPECT_TRUE(IPv4Address("172.31.255.254").is_private());
    EXPECT_TRUE(IPv4Address("172.20.13.75").is_private());
    EXPECT_FALSE(IPv4Address("172.15.0.1").is_private());
    EXPECT_FALSE(IPv4Address("172.32.0.1").is_private());
    
    EXPECT_FALSE(IPv4Address("100.100.100.100").is_private());
    EXPECT_FALSE(IPv4Address("199.199.29.10").is_private());
}

TEST(IPAddressTest, IsLoopback) {
    EXPECT_TRUE(IPv4Address("127.0.0.1").is_loopback());
    EXPECT_TRUE(IPv4Address("127.0.0.0").is_loopback());
    EXPECT_TRUE(IPv4Address("127.255.255.254").is_loopback());
    EXPECT_FALSE(IPv4Address("126.255.255.254").is_loopback());
    EXPECT_FALSE(IPv4Address("128.0.0.0").is_loopback());
}

TEST(IPAddressTest, IsMulticast) {
    EXPECT_TRUE(IPv4Address("224.0.0.1").is_multicast());
    EXPECT_TRUE(IPv4Address("226.3.54.132").is_multicast());
    EXPECT_TRUE(IPv4Address("239.255.255.255").is_multicast());
    EXPECT_FALSE(IPv4Address("223.255.255.255").is_multicast());
    EXPECT_FALSE(IPv4Address("240.0.0.0").is_multicast());
}

TEST(IPAddressTest, IsBroadcast) {
    EXPECT_TRUE(IPv4Address("255.255.255.255").is_broadcast());
    EXPECT_FALSE(IPv4Address("226.3.54.132").is_broadcast());
    EXPECT_FALSE(IPv4Address("127.0.0.1").is_broadcast());
}

TEST(IPAddressTest, IsUnicast) {
    EXPECT_FALSE(IPv4Address("255.255.255.255").is_unicast());
    EXPECT_FALSE(IPv4Address("224.0.0.1").is_unicast());
    EXPECT_TRUE(IPv4Address("240.0.0.0").is_unicast());
    EXPECT_TRUE(IPv4Address("127.0.0.1").is_unicast());
}
