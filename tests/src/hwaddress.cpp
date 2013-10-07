#include <gtest/gtest.h>
#include <algorithm>
#include <string>
#include <map>
#include <sstream>
#include <stdint.h>
#include "hw_address.h"

using namespace Tins;


class HWAddressTest : public testing::Test {
public:
    static const std::string address;
    static const uint8_t *byte_address, *empty_addr;
};

const std::string HWAddressTest::address = "00:de:ad:be:ef:00";
const uint8_t *HWAddressTest::byte_address = (const uint8_t*)"\x00\xde\xad\xbe\xef\x00",
              *HWAddressTest::empty_addr = (const uint8_t*)"\x00\x00\x00\x00\x00\x00";



TEST_F(HWAddressTest, DefaultConstructor) {
    HWAddress<6> addr;
    EXPECT_TRUE(std::equal(addr.begin(), addr.end(), empty_addr));
}

TEST_F(HWAddressTest, ShortStringConstructor) {
    HWAddress<6> addr("33:34:35"), expected("33:34:35:00:00:00");
    EXPECT_EQ(expected, addr);
}

TEST_F(HWAddressTest, EqualsOperator) {
    HWAddress<6> addr1(byte_address), addr2(byte_address);
    EXPECT_EQ(addr1, addr2);
}

TEST_F(HWAddressTest, DistinctOperator) {
    HWAddress<6> addr1(byte_address), addr2(empty_addr);
    EXPECT_NE(addr1, addr2);
}

TEST_F(HWAddressTest, SubscriptOperator) {
    HWAddress<6> addr("00:01:02:03:04:05");
    for(size_t i = 0; i < addr.size(); ++i)
        EXPECT_EQ(addr[i], i);
}

TEST_F(HWAddressTest, LessThanOperator) {
    HWAddress<6> addr1(byte_address), addr2(empty_addr);
    HWAddress<6> bcast = "ff:ff:ff:ff:ff:ff";
    EXPECT_LT(addr2, addr1);
    EXPECT_LT(addr2, bcast);
    std::map<HWAddress<6>, int> dict;
    dict[addr1] = 12;
    dict[addr2] = 15;
    EXPECT_EQ(dict[addr1], 12);
    EXPECT_EQ(dict[addr2], 15);
}


TEST_F(HWAddressTest, CopyConstructor) {
    HWAddress<6> addr1(byte_address), addr2(addr1);
    EXPECT_EQ(addr1, addr2);
}

TEST_F(HWAddressTest, IsBroadcast) {
    EXPECT_FALSE(HWAddress<6>("ff:ff:ff:ff:ff:fe").is_broadcast());
    EXPECT_FALSE(HWAddress<6>("00:01:02:03:04:05").is_broadcast());
    EXPECT_TRUE(HWAddress<6>("ff:ff:ff:ff:ff:ff").is_broadcast());
}

TEST_F(HWAddressTest, IsUnicast) {
    EXPECT_FALSE(HWAddress<6>("ff:ff:ff:ff:ff:ff").is_unicast());
    EXPECT_FALSE(HWAddress<6>("03:02:03:04:05:06").is_unicast());
    EXPECT_TRUE(HWAddress<6>("de:ad:be:ef:00:00").is_unicast());
}

TEST_F(HWAddressTest, IsMulticast) {
    EXPECT_TRUE(HWAddress<6>("01:02:03:04:05:06").is_multicast());
    EXPECT_TRUE(HWAddress<6>("09:02:03:04:05:06").is_multicast());
    EXPECT_TRUE(HWAddress<6>("03:02:03:04:05:06").is_multicast());
    EXPECT_FALSE(HWAddress<6>("00:02:03:04:05:06").is_multicast());
    EXPECT_FALSE(HWAddress<6>("02:02:03:04:05:06").is_multicast());
}

TEST_F(HWAddressTest, CopyAssignmentOperator) {
    HWAddress<6> addr1(byte_address), addr2;
    addr2 = addr1;
    EXPECT_EQ(addr1, addr2);
}

TEST_F(HWAddressTest, ConstructorFromBytes) {
    HWAddress<6> addr(byte_address);
    EXPECT_TRUE(std::equal(addr.begin(), addr.end(), byte_address));
}

TEST_F(HWAddressTest, ConstructorFromAddress) {
    HWAddress<6> addr(address);
    EXPECT_TRUE(std::equal(addr.begin(), addr.end(), byte_address));
}

TEST_F(HWAddressTest, OutputOperator) {
    HWAddress<6> addr(address);
    std::ostringstream oss;
    oss << addr;
    EXPECT_EQ(oss.str(), address);
}
