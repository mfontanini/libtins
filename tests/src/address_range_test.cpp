#include <gtest/gtest.h>
#include <cstring>
#include <string>
#include <algorithm>
#include <stdint.h>
#include "address_range.h"
#include "ip_address.h"
#include "ipv6_address.h"

using namespace std;
using namespace Tins;

class AddressRangeTest : public testing::Test {
public:
    void contain_tests24(const IPv4Range& range);
    void contain_tests24(const IPv6Range& range);
    void contain_tests26(const IPv4Range& range);
};

void AddressRangeTest::contain_tests24(const IPv4Range& range) {
    EXPECT_TRUE(range.contains("192.168.0.0"));
    EXPECT_TRUE(range.contains("192.168.0.1"));
    EXPECT_TRUE(range.contains("192.168.0.254"));
    EXPECT_TRUE(range.contains("192.168.0.255"));
    EXPECT_TRUE(range.contains("192.168.0.123"));
    EXPECT_FALSE(range.contains("192.168.1.1"));
}

void AddressRangeTest::contain_tests26(const IPv4Range& range) {
    EXPECT_TRUE(range.contains("192.168.254.192"));
    EXPECT_TRUE(range.contains("192.168.254.255"));
    EXPECT_FALSE(range.contains("192.168.254.0"));
    EXPECT_FALSE(range.contains("192.168.254.191"));
}

void AddressRangeTest::contain_tests24(const IPv6Range& range) {
    EXPECT_TRUE(range.contains("dead::1"));
    EXPECT_TRUE(range.contains("dead::1fee"));
    EXPECT_TRUE(range.contains("dead::ffee"));
    EXPECT_FALSE(range.contains("dead::1:1"));
    EXPECT_FALSE(range.contains("dead::2:0"));
}

TEST_F(AddressRangeTest, Contains) {
    contain_tests24(IPv4Range("192.168.0.0", "192.168.0.255"));
    contain_tests24(IPv4Range::from_mask("192.168.0.0", "255.255.255.0"));
    contain_tests26(IPv4Range("192.168.254.192", "192.168.254.255"));
    contain_tests26(IPv4Range::from_mask("192.168.254.192", "255.255.255.192"));
    
    contain_tests24(IPv6Range("dead::0", "dead::ffff"));
    contain_tests24(IPv6Range::from_mask("dead::0", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:0"));
    
    {
        AddressRange<HWAddress<6> > range("00:00:00:00:00:00", "00:00:00:00:00:ff");
        EXPECT_TRUE(range.contains("00:00:00:00:00:00"));
        EXPECT_TRUE(range.contains("00:00:00:00:00:10"));
        EXPECT_TRUE(range.contains("00:00:00:00:00:ff"));
        EXPECT_FALSE(range.contains("00:00:00:00:01:00"));
    }
    
    {
        AddressRange<HWAddress<6> > range = HWAddress<6>("00:00:00:00:00:00") / 40;
        EXPECT_TRUE(range.contains("00:00:00:00:00:00"));
        EXPECT_TRUE(range.contains("00:00:00:00:00:10"));
        EXPECT_TRUE(range.contains("00:00:00:00:00:ff"));
        EXPECT_FALSE(range.contains("00:00:00:00:01:00"));
    }
    
    {
        AddressRange<HWAddress<6> > range = HWAddress<6>("00:00:00:00:00:00") / 38;
        EXPECT_TRUE(range.contains("00:00:00:00:00:00"));
        EXPECT_TRUE(range.contains("00:00:00:00:02:00"));
        EXPECT_TRUE(range.contains("00:00:00:00:03:ff"));
        EXPECT_FALSE(range.contains("00:00:00:00:04:00"));
    }
}

TEST_F(AddressRangeTest, Iterators) {
    // v4
    {
        IPv4Range addr = IPv4Range::from_mask("192.168.0.0", "255.255.255.252");
        std::vector<IPv4Address> addresses;
        addresses.push_back("192.168.0.1");
        addresses.push_back("192.168.0.2");
        EXPECT_TRUE(std::equal(addr.begin(), addr.end(), addresses.begin()));
        EXPECT_TRUE(addr.is_iterable());
    }
    {
        IPv4Range addr = IPv4Range::from_mask("255.255.255.252", "255.255.255.252");
        std::vector<IPv4Address> addresses;
        addresses.push_back("255.255.255.253");
        addresses.push_back("255.255.255.254");
        EXPECT_TRUE(std::equal(addr.begin(), addr.end(), addresses.begin()));
        EXPECT_TRUE(addr.is_iterable());
    }
    
    // v6
    {
        IPv6Range addr = IPv6Range::from_mask("dead::0", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffc");
        std::vector<IPv6Address> addresses;
        addresses.push_back("dead::1");
        addresses.push_back("dead::2");
        EXPECT_TRUE(std::equal(addr.begin(), addr.end(), addresses.begin()));
        EXPECT_TRUE(addr.is_iterable());
    }
    
    {
        IPv6Range addr = 
            IPv6Range::from_mask(
                "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffc", 
                "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffc"
            );
        std::vector<IPv6Address> addresses;
        addresses.push_back("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffd");
        addresses.push_back("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe");
        EXPECT_TRUE(std::equal(addr.begin(), addr.end(), addresses.begin()));
        EXPECT_TRUE(addr.is_iterable());
    }
}

TEST_F(AddressRangeTest, Slash) {
    // v4
    {
        IPv4Range range1 = IPv4Range::from_mask("192.168.0.0", "255.255.255.252");
        IPv4Range range2 = IPv4Address("192.168.0.0") / 30;
        EXPECT_TRUE(std::equal(range1.begin(), range1.end(), range2.begin()));
        EXPECT_TRUE(std::equal(range2.begin(), range2.end(), range1.begin()));
        EXPECT_TRUE(range1.is_iterable());
        EXPECT_TRUE(range2.is_iterable());
    }
    {
        IPv4Range range1 = IPv4Range::from_mask("255.255.255.252", "255.255.255.252");
        IPv4Range range2 = IPv4Address("255.255.255.252") / 30;
        EXPECT_TRUE(std::equal(range1.begin(), range1.end(), range2.begin()));
        EXPECT_TRUE(std::equal(range2.begin(), range2.end(), range1.begin()));
        EXPECT_TRUE(range1.is_iterable());
        EXPECT_TRUE(range2.is_iterable());
    }
    
    // v6
    {
        IPv6Range range1 = IPv6Range::from_mask("dead::0", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffc");
        IPv6Range range2 = IPv6Address("dead::0") / 126;
        EXPECT_TRUE(std::equal(range1.begin(), range1.end(), range2.begin()));
        EXPECT_TRUE(std::equal(range2.begin(), range2.end(), range1.begin()));
        EXPECT_TRUE(range1.is_iterable());
        EXPECT_TRUE(range2.is_iterable());
    }
    {
        IPv6Range range1 = 
            IPv6Range::from_mask(
                "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffc", 
                "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffc"
            );
        IPv6Range range2 = IPv6Address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffc") / 126;
        EXPECT_TRUE(std::equal(range1.begin(), range1.end(), range2.begin()));
        EXPECT_TRUE(std::equal(range2.begin(), range2.end(), range1.begin()));
        EXPECT_TRUE(range1.is_iterable());
        EXPECT_TRUE(range2.is_iterable());
    }
}

TEST_F(AddressRangeTest, SlashUsingAddressGreaterThanMask) {
    // v4
    {
        IPv4Range range1 = IPv4Range::from_mask("192.168.0.128", "255.255.255.0");
        IPv4Range range2 = IPv4Address("192.168.0.0") / 24;
        EXPECT_TRUE(std::equal(range1.begin(), range1.end(), range2.begin()));
        EXPECT_TRUE(std::equal(range2.begin(), range2.end(), range1.begin()));
        EXPECT_TRUE(range1.is_iterable());
        EXPECT_TRUE(range2.is_iterable());
    }
    // v6
    {
        IPv6Range range1 = IPv6Range::from_mask("dead:beef::1200",
                                                "ffff:ffff:ffff:ffff:ffff:ffff:ffff::");
        IPv6Range range2 = IPv6Address("dead:beef::") / 112;
        EXPECT_TRUE(std::equal(range1.begin(), range1.end(), range2.begin()));
        EXPECT_TRUE(std::equal(range2.begin(), range2.end(), range1.begin()));
        EXPECT_TRUE(range1.is_iterable());
        EXPECT_TRUE(range2.is_iterable());
    }
    {
        typedef AddressRange<HWAddress<6> > HWAddressRange;
        HWAddressRange range1 = HWAddressRange::from_mask("de:ad:be:ef:fe:00", 
                                                          "ff:ff:ff:ef:00:00");
        HWAddressRange range2 = HWAddress<6>("de:ad:be:ef:00:00") / 32;
        EXPECT_TRUE(std::equal(range1.begin(), range1.end(), range2.begin()));
        EXPECT_TRUE(std::equal(range2.begin(), range2.end(), range1.begin()));
        EXPECT_TRUE(range1.is_iterable());
        EXPECT_TRUE(range2.is_iterable());
    }
}
