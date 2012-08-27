#include <gtest/gtest.h>
#include <cstring>
#include <string>
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
