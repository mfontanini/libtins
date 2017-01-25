#include <gtest/gtest.h>
#include <cstring>
#include <string>
#include <stdint.h>
#include "icmpv6.h"
#include "ethernetII.h"
#include "ip.h"
#include "tcp.h"
#include "utils.h"
#include "rawpdu.h"
#include "hw_address.h"

using namespace Tins;

class ICMPv6Test : public testing::Test {
public:
    static const uint8_t expected_packet[];
    static const uint8_t expected_packet1[];
    static const uint8_t expected_packet2[];
    static const uint8_t packet_with_extensions[];
    static const uint8_t packet_with_extensions_and_length[];
    static const uint8_t mld2_icmpv6_layer[];
    static const uint8_t mlqm_icmpv6_layer[];

    void test_equals(const ICMPv6& icmp1, const ICMPv6& icmp2);
};

const uint8_t ICMPv6Test::expected_packet[] = {
    136, 0, 220, 21, 192, 0, 0, 0, 63, 254, 5, 7, 0, 0, 0, 1, 2, 96, 151, 
    255, 254, 7, 105, 234

};

const uint8_t ICMPv6Test::expected_packet1[] = {
    134, 0, 70, 37, 64, 0, 7, 8, 0, 0, 117, 48, 0, 0, 3, 232, 1, 1, 0, 
    96, 151, 7, 105, 234, 5, 1, 0, 0, 0, 0, 5, 220, 3, 4, 64, 192, 0, 54, 
    238, 128, 0, 54, 238, 128, 0, 0, 0, 0, 63, 254, 5, 7, 0, 0, 0, 1, 0, 
    0, 0, 0, 0, 0, 0, 0
};

const uint8_t ICMPv6Test::expected_packet2[] = {
    0, 96, 151, 7, 105, 234, 0, 0, 134, 5, 128, 218, 134, 221, 96, 0,
    0, 0, 0, 32, 58, 255, 254, 128, 0, 0, 0, 0, 0, 0, 2, 0, 134, 255
    , 254, 5, 128, 218, 254, 128, 0, 0, 0, 0, 0, 0, 2, 96, 151, 255, 
    254, 7, 105, 234, 135, 0, 0, 0, 0, 0, 0, 0, 254, 128, 0, 0, 0
    , 0, 0, 0, 2, 96, 151, 255, 254, 7, 105, 234, 1, 1, 0, 0, 134, 5,
    128, 218
};

const uint8_t ICMPv6Test::packet_with_extensions[] = { 
    3, 0, 139, 66, 0, 0, 0, 0, 96, 0, 0, 0, 0, 38, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 255, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 12, 0, 99, 0, 38, 45, 93, 
    65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 
    65, 65, 65, 65, 65, 65, 65, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 
    0, 197, 95, 0, 8, 1, 1, 24, 150, 1, 1
};

const uint8_t ICMPv6Test::packet_with_extensions_and_length[] = { 
    3, 0, 139, 66, 16, 0, 0, 0, 96, 0, 0, 0, 0, 38, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 255, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 12, 0, 99, 0, 38, 45, 93, 
    65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 
    65, 65, 65, 65, 65, 65, 65, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 
    0, 197, 95, 0, 8, 1, 1, 24, 150, 1, 1
};

const uint8_t ICMPv6Test::mld2_icmpv6_layer[] = { 
    143, 0, 0, 0, 0, 0, 0, 1, 1, 2, 0, 8, 255, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 2, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 1, 255, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 255, 2, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 255, 2, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 255, 0, 0, 9, 222, 173, 190, 239, 190, 173, 254, 237
};

// Multicast Listener Query Message
const uint8_t ICMPv6Test::mlqm_icmpv6_layer[] = { 
    130, 0, 0, 0, 0, 0, 0, 0, 255, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
    8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 2, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 1, 255, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 255, 2, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 255, 2,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 255, 0, 0, 9
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
    EXPECT_EQ(icmp.reachable_time(), 30000U);
    EXPECT_EQ(icmp.retransmit_timer(), 1000U);
    const ICMPv6::option* opt = icmp.search_option(ICMPv6::SOURCE_ADDRESS);
    ASSERT_TRUE(opt != NULL);
    EXPECT_EQ(opt->data_size(), 6U);
    EXPECT_EQ(HWAddress<6>(opt->data_ptr()), "00:60:97:07:69:ea");
    
    opt = icmp.search_option(ICMPv6::MTU);
    ASSERT_TRUE(opt != NULL);
    EXPECT_EQ(opt->data_size(), 6U);
    
    opt = icmp.search_option(ICMPv6::PREFIX_INFO);
    ASSERT_TRUE(opt != NULL);
    EXPECT_EQ(opt->data_size(), 30U);
}

TEST_F(ICMPv6Test, ConstructorFromBuffer_MLD2_Layer) {
    ICMPv6 icmp(mld2_icmpv6_layer, sizeof(mld2_icmpv6_layer));

    ICMPv6::multicast_address_records_list records = icmp.multicast_address_records();
    ASSERT_EQ(1UL, records.size());
    ICMPv6::multicast_address_record r = *records.begin();
    EXPECT_EQ(1, r.type);
    std::vector<uint8_t> aux_data;
    aux_data.push_back(0xde);
    aux_data.push_back(0xad);
    aux_data.push_back(0xbe);
    aux_data.push_back(0xef);
    aux_data.push_back(0xbe);
    aux_data.push_back(0xad);
    aux_data.push_back(0xfe);
    aux_data.push_back(0xed);
    EXPECT_EQ(aux_data, r.aux_data);
    std::vector<IPv6Address> sources;
    sources.push_back("::");
    sources.push_back("ff02::1");
    sources.push_back("::");
    sources.push_back("ff02::1");
    sources.push_back("ff02::1");
    sources.push_back("ff02::2");
    sources.push_back("::1");
    sources.push_back("ff02::1:ff00:9");
    EXPECT_EQ(sources, r.sources);

    PDU::serialization_type buffer = icmp.serialize();
    EXPECT_EQ(
        PDU::serialization_type(
            mld2_icmpv6_layer, 
            mld2_icmpv6_layer + sizeof(mld2_icmpv6_layer)
        ),
        buffer
    );
}

TEST_F(ICMPv6Test, ConstructorFromBuffer_MLQM_Layer) {
    ICMPv6 icmp(mlqm_icmpv6_layer, sizeof(mlqm_icmpv6_layer));
    ICMPv6::sources_list sources;
    sources.push_back("::");
    sources.push_back("ff02::1");
    sources.push_back("::");
    sources.push_back("ff02::1");
    sources.push_back("ff02::1");
    sources.push_back("ff02::2");
    sources.push_back("::1");
    sources.push_back("ff02::1:ff00:9");
    EXPECT_EQ(sources, icmp.sources());
    EXPECT_EQ(0, icmp.supress());
    EXPECT_EQ(0, icmp.qrv());
    EXPECT_EQ(0, icmp.qqic());
    EXPECT_EQ(0, icmp.maximum_response_code());
    EXPECT_EQ(IPv6Address("ff02::1"), icmp.multicast_addr());

    PDU::serialization_type buffer = icmp.serialize();
    EXPECT_EQ(
        PDU::serialization_type(
            mlqm_icmpv6_layer, 
            mlqm_icmpv6_layer + sizeof(mlqm_icmpv6_layer)
        ),
        buffer
    );
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
    EXPECT_EQ(IPv6Address(info.prefix), IPv6Address(result.prefix));
    EXPECT_EQ(IPv6Address(result.prefix), "827d:adae::1");
}

TEST_F(ICMPv6Test, RedirectHeader) {
    ICMPv6 icmp;
    EthernetII eth = EthernetII() / IP("8.8.8.8", "192.168.0.100") / TCP(22, 26);
    PDU::serialization_type buffer = eth.serialize();
    icmp.redirect_header(buffer);
    EXPECT_EQ(buffer, icmp.redirect_header());
}

TEST_F(ICMPv6Test, MTU) {
    ICMPv6 icmp;
    ICMPv6::mtu_type data(0x1234, 0x9a8df7);
    icmp.mtu(data);
    EXPECT_EQ(data, icmp.mtu());
}

TEST_F(ICMPv6Test, ShortcutLimit) {
    ICMPv6 icmp;
    ICMPv6::shortcut_limit_type slimit(123);
    slimit.reserved1 = 0x7f;
    slimit.reserved2 = 0x12345678;
    icmp.shortcut_limit(slimit);
    ICMPv6::shortcut_limit_type sl = icmp.shortcut_limit();
    EXPECT_EQ(123, sl.limit);
    EXPECT_EQ(0x7f, sl.reserved1);
    EXPECT_EQ(0x12345678U, sl.reserved2);
}

TEST_F(ICMPv6Test, NewAdvertisementInterval) {
    ICMPv6 icmp;
    ICMPv6::new_advert_interval_type adv(0x9a8df7);
    adv.reserved = 0x1234;
    icmp.new_advert_interval(adv);
    ICMPv6::new_advert_interval_type data = icmp.new_advert_interval();
    EXPECT_EQ(0x9a8df7U, data.interval);
    EXPECT_EQ(0x1234, data.reserved);
}

TEST_F(ICMPv6Test, NewHomeAgentInformation) {
    ICMPv6 icmp;
    ICMPv6::new_ha_info_type data;
    data.push_back(0xfeed);
    data.push_back(0x92fa);
    data.push_back(0xaab3);
    icmp.new_home_agent_info(data);
    EXPECT_EQ(icmp.new_home_agent_info(), data);
}

TEST_F(ICMPv6Test, SourceAddressList) {
    ICMPv6 icmp;
    ICMPv6::addr_list_type data;
    data.addresses.push_back("827d:adae::1");
    data.addresses.push_back("2929:1234:fefe::2");
    icmp.source_addr_list(data);
    EXPECT_EQ(icmp.source_addr_list().addresses, data.addresses);
}

TEST_F(ICMPv6Test, TargetAddressList) {
    ICMPv6 icmp;
    ICMPv6::addr_list_type data;
    data.addresses.push_back("827d:adae::1");
    data.addresses.push_back("2929:1234:fefe::2");
    icmp.target_addr_list(data);
    EXPECT_EQ(icmp.target_addr_list().addresses, data.addresses);
}

TEST_F(ICMPv6Test, RSASignature) {
    ICMPv6 icmp;
    ICMPv6::rsa_sign_type data, result;
    // can i haz std::iota?
    const uint8_t arr[16] = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
    };
    std::copy(arr, arr + sizeof(arr), data.key_hash);
    data.signature.push_back(12);
    data.signature.push_back(15);
    data.signature.push_back(221);
    icmp.rsa_signature(data);
    result = icmp.rsa_signature();
    EXPECT_TRUE(std::equal(data.key_hash, data.key_hash + sizeof(data.key_hash), result.key_hash));
    // There might be some padding(in this case, there is).
    ASSERT_LE(data.signature.size(), result.signature.size());
    EXPECT_TRUE(std::equal(data.signature.begin(), data.signature.end(), result.signature.begin()));
}

TEST_F(ICMPv6Test, Timestamp) {
    ICMPv6 icmp;
    ICMPv6::timestamp_type ts(0x2837d6aaa231ULL);
    icmp.timestamp(ts);
    EXPECT_EQ(ts.timestamp, icmp.timestamp().timestamp);
}

TEST_F(ICMPv6Test, Nonce) {
    ICMPv6 icmp;
    ICMPv6::nonce_type data;
    data.push_back(22);
    data.push_back(211);
    data.push_back(67);
    icmp.nonce(data);
    EXPECT_EQ(icmp.nonce(), data);
}

TEST_F(ICMPv6Test, IPPrefix) {
    ICMPv6 icmp;
    ICMPv6::ip_prefix_type data(67, 198, "ff00:0928:ddfa::"), output;
    icmp.ip_prefix(data);
    output = icmp.ip_prefix();
    EXPECT_EQ(output.option_code, data.option_code);
    EXPECT_EQ(output.prefix_len, data.prefix_len);
    EXPECT_EQ(output.address, data.address);
}

TEST_F(ICMPv6Test, LinkLayerAddress) {
    ICMPv6 icmp;
    ICMPv6::lladdr_type data(67), output;
    data.address.push_back(87);
    data.address.push_back(22);
    data.address.push_back(185);
    icmp.link_layer_addr(data);
    output = icmp.link_layer_addr();
    EXPECT_EQ(output.option_code, data.option_code);
    ASSERT_LE(data.address.size(), output.address.size());
    EXPECT_TRUE(std::equal(data.address.begin(), data.address.end(), output.address.begin()));
}

TEST_F(ICMPv6Test, NAACK) {
    ICMPv6 icmp;
    ICMPv6::naack_type data(0x92, 0xb3), result;
    icmp.naack(data);
    result = icmp.naack();
    EXPECT_EQ(result.code, data.code);
    EXPECT_EQ(result.status, data.status);
}

TEST_F(ICMPv6Test, MAP) {
    ICMPv6 icmp;
    ICMPv6::map_type data(0x9, 0xb, 1, 0x9283719, "f029:adde::1"), output;
    icmp.map(data);
    output = icmp.map();
    EXPECT_EQ(output.dist, data.dist);
    EXPECT_EQ(output.pref, data.pref);
    EXPECT_EQ(output.r, data.r);
    EXPECT_EQ(output.valid_lifetime, data.valid_lifetime);
    EXPECT_EQ(output.address, data.address);
}

TEST_F(ICMPv6Test, RouteInfo) {
    ICMPv6 icmp;
    ICMPv6::route_info_type data(0x92, 2, 0xf23a8823), output;
    data.prefix.push_back(98);
    data.prefix.push_back(52);
    data.prefix.push_back(44);
    icmp.route_info(data);
    output = icmp.route_info();
    EXPECT_EQ(output.prefix_len, data.prefix_len);
    EXPECT_EQ(output.pref, data.pref);
    EXPECT_EQ(output.route_lifetime, data.route_lifetime);
    ASSERT_LE(data.prefix.size(), output.prefix.size());
    EXPECT_TRUE(std::equal(data.prefix.begin(), data.prefix.end(), output.prefix.begin()));
}

TEST_F(ICMPv6Test, RecursiveDNSServer) {
    ICMPv6 icmp;
    ICMPv6::recursive_dns_type data(0x9283712), output;
    data.servers.push_back("827d:adae::1");
    data.servers.push_back("2929:1234:fefe::2");
    icmp.recursive_dns_servers(data);
    output = icmp.recursive_dns_servers();
    EXPECT_EQ(output.lifetime, data.lifetime);
    EXPECT_EQ(output.servers, data.servers);
}

TEST_F(ICMPv6Test, HandoverKeyRequest) {
    ICMPv6 icmp;
    ICMPv6::handover_key_req_type data(2), output;
    data.key.push_back(98);
    data.key.push_back(52);
    data.key.push_back(44);
    icmp.handover_key_request(data);
    output = icmp.handover_key_request();
    EXPECT_EQ(output.AT, data.AT);
    EXPECT_EQ(data.key, output.key);
}

TEST_F(ICMPv6Test, HandoverKeyReply) {
    ICMPv6 icmp;
    ICMPv6::handover_key_reply_type data(0x9283, 2), output;
    data.key.push_back(98);
    data.key.push_back(52);
    data.key.push_back(44);
    icmp.handover_key_reply(data);
    output = icmp.handover_key_reply();
    EXPECT_EQ(output.AT, data.AT);
    EXPECT_EQ(output.lifetime, data.lifetime);
    EXPECT_EQ(data.key, output.key);
}

TEST_F(ICMPv6Test, HandoverAssistInfo) {
    ICMPv6 icmp;
    ICMPv6::handover_assist_info_type data(0x92), output;
    data.hai.push_back(98);
    data.hai.push_back(52);
    data.hai.push_back(44);
    icmp.handover_assist_info(data);
    output = icmp.handover_assist_info();
    EXPECT_EQ(output.option_code, data.option_code);
    EXPECT_EQ(data.hai, output.hai);
}

TEST_F(ICMPv6Test, MobileNodeIdentifier) {
    ICMPv6 icmp;
    ICMPv6::mobile_node_id_type data(0x92), output;
    data.mn.push_back(98);
    data.mn.push_back(52);
    data.mn.push_back(44);
    icmp.mobile_node_identifier(data);
    output = icmp.mobile_node_identifier();
    EXPECT_EQ(output.option_code, data.option_code);
    EXPECT_EQ(data.mn, output.mn);
}

TEST_F(ICMPv6Test, DNSSearchList) {
    ICMPv6 icmp;
    ICMPv6::dns_search_list_type data(0x9283fd1), output;
    data.domains.push_back("libtins.sourceforge.net");
    data.domains.push_back("www.example.com");
    icmp.dns_search_list(data);
    output = icmp.dns_search_list();
    EXPECT_EQ(output.lifetime, data.lifetime);
    EXPECT_EQ(data.domains, output.domains);
}

TEST_F(ICMPv6Test, MLD2Fields) {
    ICMPv6 icmp;
    ICMPv6::multicast_address_records_list records;
    ICMPv6::multicast_address_record r;
    r.type = 1;
    r.aux_data.push_back(0xde);
    r.aux_data.push_back(0xad);
    r.aux_data.push_back(0xbe);
    r.aux_data.push_back(0xef);
    r.aux_data.push_back(0xbe);
    r.aux_data.push_back(0xad);
    r.aux_data.push_back(0xfe);
    r.aux_data.push_back(0xed);
    r.sources.push_back("::");
    r.sources.push_back("ff02::1");
    r.sources.push_back("::");
    r.sources.push_back("ff02::1");
    r.sources.push_back("ff02::1");
    r.sources.push_back("ff02::2");
    r.sources.push_back("::1");
    r.sources.push_back("ff02::1:ff00:9");

    records.push_back(r);
    icmp.multicast_address_records(records);
    ICMPv6::multicast_address_records_list stored_records;
    stored_records = icmp.multicast_address_records();
    ASSERT_EQ(1U, stored_records.size());

    ICMPv6::multicast_address_record r2 = *stored_records.begin();    
    EXPECT_EQ(r.type, r2.type);
    EXPECT_EQ(r.sources, r2.sources);
    EXPECT_EQ(r.aux_data, r2.aux_data);
}

TEST_F(ICMPv6Test, MLQMFields) {
    ICMPv6 icmp;
    ICMPv6::sources_list sources;
    sources.push_back("::");
    sources.push_back("ff02::1");
    icmp.sources(sources);
    icmp.qrv(3);
    icmp.maximum_response_code(0x928a);
    icmp.supress(1);
    icmp.qqic(0xa8);
    icmp.multicast_addr("feed::beef");
    EXPECT_EQ(sources, icmp.sources());
    EXPECT_EQ(1, icmp.supress());
    EXPECT_EQ(3, icmp.qrv());
    EXPECT_EQ(0xa8, icmp.qqic());
    EXPECT_EQ(0x928a, icmp.maximum_response_code());
    EXPECT_EQ(IPv6Address("feed::beef"), icmp.multicast_addr());
}

TEST_F(ICMPv6Test, SpoofedOptions) {
    ICMPv6 pdu;
    uint8_t a[] = { 1,2,3,4,5,6 };
    pdu.add_option(
        ICMPv6::option(ICMPv6::NAACK, 250, a, a + sizeof(a))
    );
    pdu.add_option(
        ICMPv6::option(ICMPv6::NAACK, 250, a, a + sizeof(a))
    );
    pdu.add_option(
        ICMPv6::option(ICMPv6::NAACK, 250, a, a + sizeof(a))
    );
    // probably we'd expect it to crash if it's not working, valgrind plx
    EXPECT_EQ(3U, pdu.options().size());
    EXPECT_EQ(pdu.serialize().size(), pdu.size());
}

TEST_F(ICMPv6Test, ChecksumCalculation) {
    EthernetII eth(expected_packet2, sizeof(expected_packet2));
    EthernetII::serialization_type serialized = eth.serialize();
    const ICMPv6& icmp = eth.rfind_pdu<ICMPv6>();
    EXPECT_EQ(0x68bd, icmp.checksum());
}

TEST_F(ICMPv6Test, RemoveOption) {
    ICMPv6 icmp;
    PDU::serialization_type old_buffer = icmp.serialize();

    ICMPv6::recursive_dns_type data(0x9283712);
    data.servers.push_back("827d:adae::1");
    data.servers.push_back("2929:1234:fefe::2");
    icmp.recursive_dns_servers(data);
    icmp.timestamp(0x2837d6aaa231ULL);

    EXPECT_TRUE(icmp.remove_option(ICMPv6::TIMESTAMP));
    EXPECT_TRUE(icmp.remove_option(ICMPv6::RECURSIVE_DNS_SERV));

    PDU::serialization_type new_buffer = icmp.serialize();
    EXPECT_EQ(old_buffer, new_buffer);
}

TEST_F(ICMPv6Test, ExtensionsParsingWithoutALengthField) {
    const uint8_t encapsulated[] = { 96, 0, 0, 0, 0, 38, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 12, 0, 99, 0, 38, 45, 93, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    const uint8_t ext[] = { 0, 8, 1, 1, 24, 150, 1, 1 };
    ICMPv6 icmp(packet_with_extensions, sizeof(packet_with_extensions));
    ICMPExtensionsStructure extensions = icmp.extensions();
    ASSERT_EQ(1U, extensions.extensions().size());
    EXPECT_EQ(
        ICMPExtension::payload_type(ext, ext + sizeof(ext)), 
        extensions.extensions().begin()->serialize()
    );
    const RawPDU* raw = icmp.find_pdu<RawPDU>();
    ASSERT_TRUE(raw != 0);
    EXPECT_EQ(sizeof(encapsulated), raw->payload().size());
    EXPECT_EQ(
        RawPDU::payload_type(encapsulated, encapsulated + sizeof(encapsulated)),
        raw->payload()
    );
}

TEST_F(ICMPv6Test, ExtensionsParsingWithALengthField) {
    const uint8_t encapsulated[] = { 96, 0, 0, 0, 0, 38, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 12, 0, 99, 0, 38, 45, 93, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    const uint8_t ext[] = { 0, 8, 1, 1, 24, 150, 1, 1 };
    ICMPv6 icmp(packet_with_extensions_and_length, sizeof(packet_with_extensions_and_length));
    ICMPExtensionsStructure extensions = icmp.extensions();
    ASSERT_EQ(1U, extensions.extensions().size());
    EXPECT_EQ(
        ICMPExtension::payload_type(ext, ext + sizeof(ext)), 
        extensions.extensions().begin()->serialize()
    );
    const RawPDU* raw = icmp.find_pdu<RawPDU>();
    ASSERT_TRUE(raw != 0);
    EXPECT_EQ(
        RawPDU::payload_type(encapsulated, encapsulated + sizeof(encapsulated)),
        raw->payload()
    );
}
