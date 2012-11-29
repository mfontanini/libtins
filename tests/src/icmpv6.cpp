#include <gtest/gtest.h>
#include <cstring>
#include <string>
#include <stdint.h>
#include "icmpv6.h"
#include "ip.h"
#include "tcp.h"
#include "utils.h"
#include "hw_address.h"

using namespace Tins;

class ICMPv6Test : public testing::Test {
public:
    static const uint8_t expected_packet[];
    static const uint8_t expected_packet1[];

    void test_equals(const ICMPv6 &icmp1, const ICMPv6 &icmp2);
};

const uint8_t ICMPv6Test::expected_packet[] = {
    '\x88', '\x00', '\xdc', '\x15', '\xc0', '\x00', '\x00', '\x00', '?', 
    '\xfe', '\x05', '\x07', '\x00', '\x00', '\x00', '\x01', '\x02', '`', 
    '\x97', '\xff', '\xfe', '\x07', 'i', '\xea'
};

const uint8_t ICMPv6Test::expected_packet1[] = {
    '\x86', '\x00', 'F', '%', '@', '\x00', '\x07', '\x08', '\x00', '\x00', 
    'u', '0', '\x00', '\x00', '\x03', '\xe8', '\x01', '\x01', '\x00', '`', 
    '\x97', '\x07', 'i', '\xea', '\x05', '\x01', '\x00', '\x00', '\x00', 
    '\x00', '\x05', '\xdc', '\x03', '\x04', '@', '\xc0', '\x00', '6', 
    '\xee', '\x80', '\x00', '6', '\xee', '\x80', '\x00', '\x00', '\x00', 
    '\x00', '?', '\xfe', '\x05', '\x07', '\x00', '\x00', '\x00', '\x01', 
    '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00'
};

TEST_F(ICMPv6Test, Constructor) {
    ICMPv6 icmp;
    EXPECT_EQ(icmp.type(), ICMPv6::ECHO_REQUEST);
    EXPECT_EQ(icmp.code(), 0);
    EXPECT_EQ(icmp.checksum(), 0);
    EXPECT_EQ(icmp.identifier(), 0);
    EXPECT_EQ(icmp.sequence(), 0);
    EXPECT_EQ(icmp.override(), 0);
    EXPECT_EQ(icmp.solicited(), 0);
    EXPECT_EQ(icmp.router(), 0);
    EXPECT_EQ(icmp.hop_limit(), 0);
    EXPECT_EQ(icmp.router_pref(), 0);
    EXPECT_EQ(icmp.home_agent(), 0);
    EXPECT_EQ(icmp.other(), 0);
    EXPECT_EQ(icmp.managed(), 0);
    EXPECT_EQ(icmp.router_lifetime(), 0);
}

TEST_F(ICMPv6Test, ConstructorFromBuffer) {
    ICMPv6 icmp(expected_packet, sizeof(expected_packet));
    EXPECT_EQ(icmp.type(), ICMPv6::NEIGHBOUR_ADVERT);
    EXPECT_EQ(icmp.code(), 0);
    EXPECT_EQ(icmp.checksum(), 0xdc15);
    EXPECT_EQ(icmp.solicited(), 1);
    EXPECT_EQ(icmp.router(), 1);
    EXPECT_EQ(icmp.override(), 0);
    EXPECT_EQ(icmp.target_addr(), "3ffe:507:0:1:260:97ff:fe07:69ea");
}

TEST_F(ICMPv6Test, ConstructorFromBuffer2) {
    ICMPv6 icmp(expected_packet1, sizeof(expected_packet1));
    EXPECT_EQ(icmp.type(), ICMPv6::ROUTER_ADVERT);
    EXPECT_EQ(icmp.code(), 0);
    EXPECT_EQ(icmp.checksum(), 0x4625);
    EXPECT_EQ(icmp.managed(), 0);
    EXPECT_EQ(icmp.home_agent(), 0);
    EXPECT_EQ(icmp.other(), 0);
    EXPECT_EQ(icmp.router_pref(), 0);
    EXPECT_EQ(icmp.router_lifetime(), 1800);
    EXPECT_EQ(icmp.reachable_time(), 30000);
    EXPECT_EQ(icmp.retransmit_timer(), 1000);
    const ICMPv6::icmpv6_option *opt = icmp.search_option(ICMPv6::SOURCE_ADDRESS);
    ASSERT_TRUE(opt);
    EXPECT_EQ(opt->data_size(), 6);
    EXPECT_EQ(HWAddress<6>(opt->data_ptr()), "00:60:97:07:69:ea");
    
    opt = icmp.search_option(ICMPv6::MTU);
    ASSERT_TRUE(opt);
    EXPECT_EQ(opt->data_size(), 6);
    
    opt = icmp.search_option(ICMPv6::PREFIX_INFO);
    ASSERT_TRUE(opt);
    EXPECT_EQ(opt->data_size(), 30);
}

TEST_F(ICMPv6Test, Type) {
    ICMPv6 icmp;
    icmp.type(ICMPv6::MLD2_REPORT);
    EXPECT_EQ(icmp.type(), ICMPv6::MLD2_REPORT);
}

TEST_F(ICMPv6Test, Code) {
    ICMPv6 icmp;
    icmp.code(0x7a);
    EXPECT_EQ(icmp.code(), 0x7a);
}

TEST_F(ICMPv6Test, Checksum) {
    ICMPv6 icmp;
    icmp.checksum(0x827f);
    EXPECT_EQ(icmp.checksum(), 0x827f);
}

TEST_F(ICMPv6Test, Identifier) {
    ICMPv6 icmp;
    icmp.identifier(0x827f);
    EXPECT_EQ(icmp.identifier(), 0x827f);
}

TEST_F(ICMPv6Test, Sequence) {
    ICMPv6 icmp;
    icmp.sequence(0x827f);
    EXPECT_EQ(icmp.sequence(), 0x827f);
}

TEST_F(ICMPv6Test, Override) {
    ICMPv6 icmp;
    icmp.override(1);
    EXPECT_EQ(icmp.override(), 1);
    icmp.override(0);
    EXPECT_EQ(icmp.override(), 0);
}

TEST_F(ICMPv6Test, Solicited) {
    ICMPv6 icmp;
    icmp.solicited(1);
    EXPECT_EQ(icmp.solicited(), 1);
    icmp.solicited(0);
    EXPECT_EQ(icmp.solicited(), 0);
}

TEST_F(ICMPv6Test, Router) {
    ICMPv6 icmp;
    icmp.router(1);
    EXPECT_EQ(icmp.router(), 1);
    icmp.router(0);
    EXPECT_EQ(icmp.router(), 0);
}

TEST_F(ICMPv6Test, RouterPref) {
    ICMPv6 icmp;
    icmp.router_pref(1);
    EXPECT_EQ(icmp.router_pref(), 1);
    icmp.router_pref(0);
    EXPECT_EQ(icmp.router_pref(), 0);
}

TEST_F(ICMPv6Test, HomeAgent) {
    ICMPv6 icmp;
    icmp.home_agent(1);
    EXPECT_EQ(icmp.home_agent(), 1);
    icmp.home_agent(0);
    EXPECT_EQ(icmp.home_agent(), 0);
}

TEST_F(ICMPv6Test, Other) {
    ICMPv6 icmp;
    icmp.other(1);
    EXPECT_EQ(icmp.other(), 1);
    icmp.other(0);
    EXPECT_EQ(icmp.other(), 0);
}

TEST_F(ICMPv6Test, Managed) {
    ICMPv6 icmp;
    icmp.managed(1);
    EXPECT_EQ(icmp.managed(), 1);
    icmp.managed(0);
    EXPECT_EQ(icmp.managed(), 0);
}

TEST_F(ICMPv6Test, RTLifetime) {
    ICMPv6 icmp;
    icmp.router_lifetime(0x827f);
    EXPECT_EQ(icmp.router_lifetime(), 0x827f);
}

TEST_F(ICMPv6Test, SourceLinkLayerAddress) {
    ICMPv6 icmp;
    icmp.source_link_layer_addr("09:fe:da:fe:22:33");
    EXPECT_EQ(icmp.source_link_layer_addr(), "09:fe:da:fe:22:33");
}

TEST_F(ICMPv6Test, TargetLinkLayerAddress) {
    ICMPv6 icmp;
    icmp.target_link_layer_addr("09:fe:da:fe:22:33");
    EXPECT_EQ(icmp.target_link_layer_addr(), "09:fe:da:fe:22:33");
}

TEST_F(ICMPv6Test, PrefixInformation) {
    ICMPv6 icmp;
    ICMPv6::prefix_info_type result, info(0x8, 1, 0, 0x92038fad, 
        0x918273fa, "827d:adae::1");
    icmp.prefix_info(info);
    result = icmp.prefix_info();
    EXPECT_EQ(result.prefix_len, info.prefix_len);
    EXPECT_EQ(result.A, info.A);
    EXPECT_EQ(result.L, info.L);
    EXPECT_EQ(result.valid_lifetime, info.valid_lifetime);
    EXPECT_EQ(result.preferred_lifetime, info.preferred_lifetime);
    EXPECT_EQ(IPv6Address(result.prefix), IPv6Address(result.prefix));
    EXPECT_EQ(IPv6Address(result.prefix), "827d:adae::1");
}

TEST_F(ICMPv6Test, RedirectHeader) {
    ICMPv6 icmp;
    IP ip = IP("127.0.0.1") / TCP(22);
    PDU::serialization_type buffer = ip.serialize();
    icmp.redirect_header(buffer);
    EXPECT_EQ(buffer, icmp.redirect_header());
}

TEST_F(ICMPv6Test, MTU) {
    ICMPv6 icmp;
    icmp.mtu(0x9a8df7);
    EXPECT_EQ(icmp.mtu(), 0x9a8df7);
}

TEST_F(ICMPv6Test, ShortcutLimit) {
    ICMPv6 icmp;
    icmp.shortcut_limit(123);
    EXPECT_EQ(icmp.shortcut_limit(), 123);
}

TEST_F(ICMPv6Test, NewAdvertisementInterval) {
    ICMPv6 icmp;
    icmp.new_advert_interval(0x9a8df7);
    EXPECT_EQ(icmp.new_advert_interval(), 0x9a8df7);
}

TEST_F(ICMPv6Test, NewHomeAgentInformation) {
    ICMPv6 icmp;
    ICMPv6::new_ha_info_type data(0x92fa, 0xaab3);
    icmp.new_home_agent_info(data);
    EXPECT_EQ(icmp.new_home_agent_info(), data);
}
