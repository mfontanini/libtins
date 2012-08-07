#include <gtest/gtest.h>
#include <algorithm>
#include <string>
#include <sstream>
#include <stdint.h>
#include "hwaddress.h"

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
