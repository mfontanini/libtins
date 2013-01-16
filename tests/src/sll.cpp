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
    
    void test_equals(const SLL &sll1, const SLL &sll2);
};

const uint8_t SLLTest::expected_packet[] = { 
    '\x00', '\x00', '\x00', '\x01', '\x00', '\x06', '\x00', '\x1b', '\x11', 
    '\xd2', '\x1b', '\xeb', '\x00', '\x00', '\x08', '\x00', 'E', '\x00', 
    '\x00', 't', 'A', '\x12', '\x00', '\x00', ',', '\x06', '\x9c', '6', 
    '\xad', '\xc2', 'B', 'm', '\xc0', '\xa8', '\x00', 'd', '\x03', '\xe1', 
    '\x8d', '\x04', '7', '=', '\x96', '\xa1', 'U', 'j', 'I', '\xbd', '\x80', 
    '\x18', '\x01', '\x00', '\xca', 'w', '\x00', '\x00', '\x01', '\x01', 
    '\x08', '\n', 'G', '-', '(', '\xab', '\x00', '\x13', 'N', 'V', '\x17', 
    '\x03', '\x01', '\x00', ';', '\xa8', '\x93', '\xb6', '\x96', '\x9f', 
    '\xb2', '\xcc', 't', '>', 'U', 'P', '\xa7', '\x17', '\x18', '\xad', 
    '\xec', '7', '.', '\xbe', '\xcd', '\xff', '\x13', '\xf8', '\x81', 
    '\xc6', '\x8c', '\xd0', '<', 'O', ';', '&', '\xa5', '\x83', '!', 'i', 
    '\xd4', 'p', '\xae', 'P', '\xd3', '0', '%', 't', 'l', 'm', '!', '$', 
    '\xe7', '\x9a', '\x83', 'p', '\xf6', '\x03', '\xb4', '\xc7', '\x9e', 
    '\xcd', '{', '\xee'
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
    
    ASSERT_TRUE(sll.inner_pdu());
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
