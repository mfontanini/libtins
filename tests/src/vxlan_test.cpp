#include <gtest/gtest.h>
#include <string>
#include <tins/ethernetII.h>
#include <tins/ip.h>
#include <tins/tcp.h>
#include <tins/udp.h>
#include <tins/pdu.h>
#include <tins/small_uint.h>
#include <tins/vxlan.h>

#define PACKET_SIZE 68ul

using namespace std;
using namespace Tins;

class VXLANTest : public testing::Test {
public:
    static const uint8_t expected_packet[PACKET_SIZE];
    static const uint8_t flags;
    static const uint16_t dport, sport, p_type;
    static const small_uint<24> vni;
    static const IP::address_type dst_ip, src_ip;
    static const EthernetII::address_type dst_addr, src_addr;
};

const uint8_t VXLANTest::expected_packet[PACKET_SIZE] = {
    0x08, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0x00,
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

const uint8_t VXLANTest::flags = 8;
const uint16_t VXLANTest::dport = 19627;
const uint16_t VXLANTest::sport = 4789;
const uint16_t VXLANTest::p_type = 0xd0ab;
const small_uint<24> VXLANTest::vni = 0xffffff;
const IP::address_type VXLANTest::dst_ip = IP::address_type{"2.2.2.2"};
const IP::address_type VXLANTest::src_ip = IP::address_type{"1.1.1.1"};
const EthernetII::address_type VXLANTest::dst_addr = EthernetII::address_type{"aa:bb:cc:dd:ee:ff"};
const EthernetII::address_type VXLANTest::src_addr = EthernetII::address_type{"8a:8b:8c:8d:8e:8f"};

TEST_F(VXLANTest, Flags) {
    auto const vxlan = VXLAN{};
    EXPECT_EQ(vxlan.get_flags(), flags);
}

TEST_F(VXLANTest, VNI) {
    auto const vxlan = VXLAN{vni};
    EXPECT_EQ(vxlan.get_vni(), vni);
}

TEST_F(VXLANTest, Find) {
    auto const pdu = VXLAN{} / EthernetII{dst_addr, src_addr};
    auto const eth = pdu.find_pdu<EthernetII>();
    ASSERT_TRUE(eth != nullptr);
    EXPECT_EQ(eth->dst_addr(), dst_addr);
    EXPECT_EQ(eth->src_addr(), src_addr);
}

TEST_F(VXLANTest, Serialize) {
    auto eth = EthernetII{dst_addr, src_addr};
    eth.payload_type(p_type);
    auto vxlan = VXLAN{vni};
    vxlan.inner_pdu(eth);
    auto serialized = vxlan.serialize();
    ASSERT_EQ(serialized.size(), PACKET_SIZE);
    EXPECT_TRUE(std::equal(serialized.begin(), serialized.end(), expected_packet));
}

TEST_F(VXLANTest, ConstructorFromBuffer) {
    auto vxlan = VXLAN{expected_packet, PACKET_SIZE};
    EXPECT_EQ(vxlan.get_vni(), vni);
    EXPECT_EQ(vxlan.get_flags(), flags);
    auto const eth = vxlan.find_pdu<EthernetII>();
    ASSERT_TRUE(eth != nullptr);
    EXPECT_EQ(eth->dst_addr(), dst_addr);
    EXPECT_EQ(eth->src_addr(), src_addr);
}

TEST_F(VXLANTest, OuterUDP) {
    auto pkt = IP{dst_ip, src_ip} / UDP{dport, sport} / VXLAN{expected_packet, PACKET_SIZE};
    auto const vxlan = pkt.find_pdu<VXLAN>();
    ASSERT_TRUE(vxlan != nullptr);
    EXPECT_EQ(vxlan->get_flags(), flags);
    EXPECT_EQ(vxlan->get_vni(), vni);
}
