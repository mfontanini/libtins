#include <cstring>
#include <gtest/gtest.h>
#include <stdint.h>
#include <tins/constants.h>
#include <tins/hw_address.h>
#include <tins/ip.h>
#include <tins/sll2.h>

using namespace std;
using namespace Tins;

class SLL2Test : public testing::Test {
public:
  static const uint8_t expected_packet[];

  void test_equals(const SLL2 &, const SLL2 &);
};

const uint8_t SLL2Test::expected_packet[] = {
    8,   0,   0,   0,   0,   0,   1,   27,  0,  1,0, 6,   0,   27,  17,  210, 27,
    235, 0,   0,   69,  0,   0,   116, 65,  18,  0,   0,   44,  6,   156, 54,
    173, 194, 66,  109, 192, 168, 0,   100, 3,   225, 141, 4,   55,  61,  150,
    161, 85,  106, 73,  189, 128, 24,  1,   0,   202, 119, 0,   0,   1,   1,
    8,   10,  71,  45,  40,  171, 0,   19,  78,  86,  23,  3,   1,   0,   59,
    168, 147, 182, 150, 159, 178, 204, 116, 62,  85,  80,  167, 23,  24,  173,
    236, 55,  46,  190, 205, 255, 19,  248, 129, 198, 140, 208, 60,  79,  59,
    38,  165, 131, 33,  105, 212, 112, 174, 80,  211, 48,  37,  116, 108, 109,
    33,  36,  231, 154, 131, 112, 246, 3,   180, 199, 158, 205, 123, 238};

TEST_F(SLL2Test, DefaultConstructor) {
  SLL2 sll2;
  EXPECT_EQ(0, sll2.protocol());
  EXPECT_EQ(0, sll2.interface_index());
  EXPECT_EQ(0, sll2.lladdr_type());
  EXPECT_EQ(0, sll2.packet_type());
  EXPECT_EQ(0, sll2.lladdr_len());
  EXPECT_EQ(SLL2::address_type("00:00:00:00:00:00:00:00"), sll2.address());
}

TEST_F(SLL2Test, ConstructorFromBuffer) {
  typedef HWAddress<6> address_type;
  address_type addr("00:1b:11:d2:1b:eb");
  SLL2 sll2(expected_packet, sizeof(expected_packet));
  EXPECT_EQ(Constants::Ethernet::IP, sll2.protocol());
  EXPECT_EQ(283, sll2.interface_index());
  EXPECT_EQ(1, sll2.lladdr_type());
  EXPECT_EQ(0, sll2.packet_type());
  EXPECT_EQ(6, sll2.lladdr_len());
  EXPECT_EQ(addr, sll2.address());

  ASSERT_TRUE(sll2.inner_pdu() != NULL);
  EXPECT_EQ(sll2.find_pdu<IP>(), sll2.inner_pdu());
}

TEST_F(SLL2Test, Serialize) {
  SLL2 sll2(expected_packet, sizeof(expected_packet));
  SLL2::serialization_type buffer = sll2.serialize();
  ASSERT_EQ(sizeof(expected_packet), buffer.size());
  EXPECT_TRUE(std::equal(buffer.begin(), buffer.end(), expected_packet));
}

TEST_F(SLL2Test, Protocol) {
  SLL2 sll2;
  sll2.protocol(0x923f);
  EXPECT_EQ(0x923f, sll2.protocol());
}

TEST_F(SLL2Test, InterfaceIndex) {
  SLL2 sll2;
  sll2.interface_index(0x1234923f);
  EXPECT_EQ(0x1234923f, sll2.interface_index());
}

TEST_F(SLL2Test, LLADDRType) {
  SLL2 sll;
  sll.lladdr_type(0x923f);
  EXPECT_EQ(0x923f, sll.lladdr_type());
}

TEST_F(SLL2Test, PacketType) {
  SLL2 sll;
  sll.packet_type(0x3f);
  EXPECT_EQ(0x3f, sll.packet_type());
}

TEST_F(SLL2Test, LLADDRLen) {
  SLL2 sll2;
  sll2.lladdr_len(0x92);
  EXPECT_EQ(0x92, sll2.lladdr_len());
}

TEST_F(SLL2Test, Address) {
  HWAddress<6> addr = "00:01:02:03:04:05";
  SLL2 sll2;
  sll2.address(addr);
  EXPECT_EQ(addr, sll2.address());
}
