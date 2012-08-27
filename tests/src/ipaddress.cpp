#include <gtest/gtest.h>
#include <cstring>
#include <string>
#include <sstream>
#include <stdint.h>
#include "ipaddress.h"
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
