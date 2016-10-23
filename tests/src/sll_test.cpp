#include <gtest/gtest.h>
#include <cstring>
#include <string>
#include <stdint.h>
#include "sll.h"
#include "hw_address.h"
#include "constants.h"
#include "ip.h"

using namespace std;
using namespace Tins;

class SLLTest : public testing::Test {
public:
    static const uint8_t expected_packet[];
    
    void test_equals(const SLL& sll1, const SLL& sll2);
};

const uint8_t SLLTest::expected_packet[] = { 
    0, 0, 0, 1, 0, 6, 0, 27, 17, 210, 27, 235, 0, 0, 8, 0, 69, 0, 0, 116, 
    65, 18, 0, 0, 44, 6, 156, 54, 173, 194, 66, 109, 192, 168, 0, 100, 
    3, 225, 141, 4, 55, 61, 150, 161, 85, 106, 73, 189, 128, 24, 1, 0, 
    202, 119, 0, 0, 1, 1, 8, 10, 71, 45, 40, 171, 0, 19, 78, 86, 23, 3, 
    1, 0, 59, 168, 147, 182, 150, 159, 178, 204, 116, 62, 85, 80, 167, 
    23, 24, 173, 236, 55, 46, 190, 205, 255, 19, 248, 129, 198, 140, 208, 
    60, 79, 59, 38, 165, 131, 33, 105, 212, 112, 174, 80, 211, 48, 37, 
    116, 108, 109, 33, 36, 231, 154, 131, 112, 246, 3, 180, 199, 158, 205, 
    123, 238
};

TEST_F(SLLTest, DefaultConstructor) {
    SLL sll;
    EXPECT_EQ(0, sll.packet_type());
    EXPECT_EQ(0, sll.lladdr_type());
    EXPECT_EQ(0, sll.lladdr_len());
    EXPECT_EQ(0, sll.protocol());
    EXPECT_EQ(SLL::address_type("00:00:00:00:00:00:00:00"), sll.address());
}

TEST_F(SLLTest, ConstructorFromBuffer) {
    typedef HWAddress<6> address_type;
    address_type addr("00:1b:11:d2:1b:eb");
    SLL sll(expected_packet, sizeof(expected_packet));
    EXPECT_EQ(0, sll.packet_type());
    EXPECT_EQ(1, sll.lladdr_type());
    EXPECT_EQ(6, sll.lladdr_len());
    EXPECT_EQ(Constants::Ethernet::IP, sll.protocol());
    EXPECT_EQ(addr, sll.address());
    
    ASSERT_TRUE(sll.inner_pdu() != NULL);
    EXPECT_EQ(sll.find_pdu<IP>(), sll.inner_pdu());
}

TEST_F(SLLTest, Serialize) {
    SLL sll(expected_packet, sizeof(expected_packet));
    SLL::serialization_type buffer = sll.serialize();
    ASSERT_EQ(sizeof(expected_packet), buffer.size());
    EXPECT_TRUE(std::equal(buffer.begin(), buffer.end(), expected_packet));
}

TEST_F(SLLTest, PacketType) {
    SLL sll;
    sll.packet_type(0x923f);
    EXPECT_EQ(0x923f, sll.packet_type());
}

TEST_F(SLLTest, LLADDRType) {
    SLL sll;
    sll.lladdr_type(0x923f);
    EXPECT_EQ(0x923f, sll.lladdr_type());
}

TEST_F(SLLTest, LLADDRLen) {
    SLL sll;
    sll.lladdr_len(0x923f);
    EXPECT_EQ(0x923f, sll.lladdr_len());
}

TEST_F(SLLTest, Protocol) {
    SLL sll;
    sll.protocol(0x923f);
    EXPECT_EQ(0x923f, sll.protocol());
}

TEST_F(SLLTest, Address) {
    HWAddress<6> addr = "00:01:02:03:04:05";
    SLL sll;
    sll.address(addr);
    EXPECT_EQ(addr, sll.address());
}
