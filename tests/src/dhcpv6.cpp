#include <gtest/gtest.h>
#include <cstring>
#include <string>
#include <stdint.h>
#include "dhcpv6.h"

using namespace Tins;

class DHCPv6Test : public testing::Test {
public:
    static const uint8_t expected_packet[];

    void test_equals(const DHCPv6& dhcp1, const DHCPv6& dhcp2);
};

const uint8_t DHCPv6Test::expected_packet[] = {
    1, 232, 40, 185, 0, 1, 0, 10, 0, 3, 0, 1, 0, 1, 2, 3, 4, 5, 0, 3, 0, 
    12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 2, 0, 0, 0, 6, 0, 
    2, 0, 3
};

TEST_F(DHCPv6Test, DefaultConstructor) {
    DHCPv6 dhcp;
    EXPECT_EQ(0, (int)dhcp.msg_type());
    EXPECT_EQ(0, dhcp.hop_count());
    EXPECT_EQ(0U, dhcp.transaction_id());
}

TEST_F(DHCPv6Test, ConstructorFromBuffer) {
    DHCPv6 dhcp(expected_packet, sizeof(expected_packet));
    EXPECT_EQ(DHCPv6::SOLICIT, dhcp.msg_type());
    EXPECT_EQ(0xe828b9U, dhcp.transaction_id());
    EXPECT_TRUE(dhcp.search_option(DHCPv6::CLIENTID) != NULL);
    EXPECT_TRUE(dhcp.search_option(DHCPv6::IA_NA) != NULL);
    EXPECT_TRUE(dhcp.search_option(DHCPv6::ELAPSED_TIME) != NULL);
    EXPECT_TRUE(dhcp.search_option(DHCPv6::OPTION_REQUEST) != NULL);
    EXPECT_FALSE(dhcp.search_option(DHCPv6::SERVERID) != NULL);
}

TEST_F(DHCPv6Test, Serialize) {
    DHCPv6 dhcp(expected_packet, sizeof(expected_packet));
    DHCPv6::serialization_type buffer = dhcp.serialize();
    ASSERT_EQ(sizeof(expected_packet), buffer.size());
    EXPECT_EQ(
        DHCPv6::serialization_type(expected_packet, expected_packet + sizeof(expected_packet)),
        buffer
    );
}

TEST_F(DHCPv6Test, MessageType) {
    DHCPv6 dhcp;
    dhcp.msg_type(DHCPv6::SOLICIT);
    EXPECT_EQ(DHCPv6::SOLICIT, dhcp.msg_type());
}

TEST_F(DHCPv6Test, HopCount) {
    DHCPv6 dhcp;
    dhcp.hop_count(0x8a);
    EXPECT_EQ(0x8a, dhcp.hop_count());
}

TEST_F(DHCPv6Test, TransactionId) {
    DHCPv6 dhcp;
    dhcp.transaction_id(0x8af2ad);
    EXPECT_EQ(0x8af2adU, dhcp.transaction_id());
}

// Options

TEST_F(DHCPv6Test, IA_NA) {
    DHCPv6 dhcp;
    DHCPv6::ia_na_type data, output;
    data.id = 0x9283f78a;
    data.t1 = 0xaf235212;
    data.t2 = 0x9a8293fa;
    data.options.push_back(0);
    data.options.push_back(1);
    data.options.push_back(2);
    dhcp.ia_na(data);
    output = dhcp.ia_na();
    
    EXPECT_EQ(data.id, output.id);
    EXPECT_EQ(data.t1, output.t1);
    EXPECT_EQ(data.t2, output.t2);
    EXPECT_EQ(data.options, output.options);
}

TEST_F(DHCPv6Test, IA_TA) {
    DHCPv6 dhcp;
    DHCPv6::ia_ta_type data, output;
    data.id = 0x9283f78a;
    data.options.push_back(0);
    data.options.push_back(1);
    data.options.push_back(2);
    dhcp.ia_ta(data);
    output = dhcp.ia_ta();
    
    EXPECT_EQ(data.id, output.id);
    EXPECT_EQ(data.options, output.options);
}

TEST_F(DHCPv6Test, IA_Address) {
    DHCPv6 dhcp;
    DHCPv6::ia_address_type data, output;
    data.address = "fe00:feaa::1";
    data.preferred_lifetime = 0x9283f78a;
    data.valid_lifetime = 0x938fda32;
    data.options.push_back(0);
    data.options.push_back(1);
    data.options.push_back(2);
    dhcp.ia_address(data);
    output = dhcp.ia_address();
    
    EXPECT_EQ(data.address, output.address);
    EXPECT_EQ(data.preferred_lifetime, output.preferred_lifetime);
    EXPECT_EQ(data.valid_lifetime, output.valid_lifetime);
    EXPECT_EQ(data.options, output.options);
}

TEST_F(DHCPv6Test, OptionRequest) {
    DHCPv6 dhcp;
    DHCPv6::option_request_type data, output;
    data.push_back(DHCPv6::IA_ADDR);
    data.push_back(DHCPv6::IA_NA);
    
    dhcp.option_request(data);
    output = dhcp.option_request();
    
    EXPECT_EQ(data, output);
}

TEST_F(DHCPv6Test, Preference) {
    DHCPv6 dhcp;
    dhcp.preference(0x8a);
    EXPECT_EQ(0x8a, dhcp.preference());
}

TEST_F(DHCPv6Test, ElapsedTime) {
    DHCPv6 dhcp;
    dhcp.elapsed_time(0x8a2f);
    EXPECT_EQ(0x8a2f, dhcp.elapsed_time());
}

TEST_F(DHCPv6Test, RelayMessage) {
    DHCPv6 dhcp;
    DHCPv6::relay_msg_type data, output;
    data.push_back(1);
    data.push_back(156);
    data.push_back(12);
    
    dhcp.relay_message(data);
    output = dhcp.relay_message();
    
    EXPECT_EQ(data, output);
}

TEST_F(DHCPv6Test, Authentication) {
    DHCPv6 dhcp;
    DHCPv6::authentication_type data, output;
    data.protocol = 0x92;
    data.algorithm = 0x8f;
    data.rdm = 0xa1;
    data.replay_detection = 0x78ad6d5290398df7ULL;
    data.auth_info.push_back(0);
    data.auth_info.push_back(1);
    data.auth_info.push_back(2);
    dhcp.authentication(data);
    output = dhcp.authentication();
    
    EXPECT_EQ(data.protocol, output.protocol);
    EXPECT_EQ(data.algorithm, output.algorithm);
    EXPECT_EQ(data.rdm, output.rdm);
    EXPECT_EQ(data.replay_detection, output.replay_detection);
    EXPECT_EQ(data.auth_info, output.auth_info);
}

TEST_F(DHCPv6Test, ServerUnicast) {
    const IPv6Address addr("fe00:0a9d:dd23::1");
    DHCPv6 dhcp;
    dhcp.server_unicast(addr);
    EXPECT_EQ(addr, dhcp.server_unicast());
}

TEST_F(DHCPv6Test, StatusCode) {
    DHCPv6 dhcp;
    DHCPv6::status_code_type data(0x72, "libtins, mah frend"), output;
    dhcp.status_code(data);
    output = dhcp.status_code();
    EXPECT_EQ(data.code, output.code);
    EXPECT_EQ(data.message, output.message);
}

TEST_F(DHCPv6Test, RapidCommit) {
    DHCPv6 dhcp;
    dhcp.rapid_commit();
    EXPECT_EQ(true, dhcp.has_rapid_commit());
}

TEST_F(DHCPv6Test, UserClass) {
    DHCPv6 dhcp;
    DHCPv6::user_class_type data, output;
    DHCPv6::class_option_data_type user_data;
    user_data.push_back(22);
    user_data.push_back(176);
    data.data.push_back(user_data);
    
    user_data.push_back(99);
    user_data.push_back(231);
    data.data.push_back(user_data);
    
    dhcp.user_class(data);
    output = dhcp.user_class();
    
    EXPECT_EQ(data.data, output.data);
}

TEST_F(DHCPv6Test, VendorClass) {
    DHCPv6 dhcp;
    DHCPv6::vendor_class_type data(15), output;
    DHCPv6::class_option_data_type user_data;
    user_data.push_back(22);
    user_data.push_back(176);
    data.vendor_class_data.push_back(user_data);
    
    user_data.push_back(99);
    user_data.push_back(231);
    data.vendor_class_data.push_back(user_data);
    
    dhcp.vendor_class(data);
    output = dhcp.vendor_class();
    
    EXPECT_EQ(data.enterprise_number, output.enterprise_number);
    EXPECT_EQ(data.vendor_class_data, output.vendor_class_data);
}

TEST_F(DHCPv6Test, VendorInfo) {
    DHCPv6 dhcp;
    DHCPv6::vendor_info_type data(0x72988fad), output;
    data.data.push_back(22);
    data.data.push_back(176);
    data.data.push_back(99);
    data.data.push_back(231);
    
    dhcp.vendor_info(data);
    output = dhcp.vendor_info();
    
    EXPECT_EQ(data.enterprise_number, output.enterprise_number);
    EXPECT_EQ(data.data, output.data);
}

TEST_F(DHCPv6Test, InterfaceID) {
    DHCPv6 dhcp;
    DHCPv6::interface_id_type data, output;
    data.push_back(1);
    data.push_back(156);
    data.push_back(12);
    
    dhcp.interface_id(data);
    output = dhcp.interface_id();
    
    EXPECT_EQ(data, output);
}

TEST_F(DHCPv6Test, ReconfigureMsg) {
    DHCPv6 dhcp;
    dhcp.reconfigure_msg(0x8a);
    EXPECT_EQ(0x8a, dhcp.reconfigure_msg());
}

TEST_F(DHCPv6Test, ReconfigureAccept) {
    DHCPv6 dhcp;
    dhcp.reconfigure_accept();
    EXPECT_EQ(true, dhcp.has_reconfigure_accept());
}

TEST_F(DHCPv6Test, Client_Server_ID_DUIDLL) {
    DHCPv6 dhcp;
    DHCPv6::duid_ll data, output;
    DHCPv6::duid_type tmp, tmp2;
    data.hw_type = 0x5f;
    data.lladdress.push_back(78);
    data.lladdress.push_back(66);
    data.lladdress.push_back(209);
    dhcp.client_id(data);
    tmp = dhcp.client_id();
    output = DHCPv6::duid_ll::from_bytes(&tmp.data[0], (uint32_t)tmp.data.size());
    EXPECT_EQ(data.hw_type, output.hw_type);
    EXPECT_EQ(data.lladdress, output.lladdress);
    
    dhcp.server_id(data);
    tmp2 = dhcp.server_id();
    EXPECT_EQ(tmp.id, tmp2.id);
    EXPECT_EQ(tmp.data, tmp2.data);
}

TEST_F(DHCPv6Test, Client_Server_ID_DUIDLLT) {
    DHCPv6 dhcp;
    DHCPv6::duid_llt data, output;
    DHCPv6::duid_type tmp, tmp2;
    data.hw_type = 0x5f;
    data.time = 0x92837af;
    data.lladdress.push_back(78);
    data.lladdress.push_back(66);
    data.lladdress.push_back(209);
    dhcp.client_id(data);
    tmp = dhcp.client_id();
    output = DHCPv6::duid_llt::from_bytes(&tmp.data[0], (uint32_t)tmp.data.size());
    EXPECT_EQ(data.hw_type, output.hw_type);
    EXPECT_EQ(data.time, output.time);
    EXPECT_EQ(data.lladdress, output.lladdress);
    
    dhcp.server_id(data);
    tmp2 = dhcp.server_id();
    EXPECT_EQ(tmp.id, tmp2.id);
    EXPECT_EQ(tmp.data, tmp2.data);
}

TEST_F(DHCPv6Test, Client_Server_ID_DUIDEN) {
    DHCPv6 dhcp;
    DHCPv6::duid_en data, output;
    DHCPv6::duid_type tmp, tmp2;
    data.enterprise_number = 0x5faa23da;
    data.identifier.push_back(78);
    data.identifier.push_back(66);
    data.identifier.push_back(209);
    dhcp.client_id(data);
    tmp = dhcp.client_id();
    output = DHCPv6::duid_en::from_bytes(&tmp.data[0], (uint32_t)tmp.data.size());
    EXPECT_EQ(data.enterprise_number, output.enterprise_number);
    EXPECT_EQ(data.identifier, output.identifier);
    
    dhcp.server_id(data);
    tmp2 = dhcp.server_id();
    EXPECT_EQ(tmp.id, tmp2.id);
    EXPECT_EQ(tmp.data, tmp2.data);
}

TEST_F(DHCPv6Test, RemoveOption) {
    DHCPv6 dhcp;
    PDU::serialization_type old_buffer = dhcp.serialize();

    dhcp.server_unicast("fe00:0a9d:dd23::1");
    dhcp.preference(12);

    EXPECT_TRUE(dhcp.remove_option(DHCPv6::UNICAST));
    EXPECT_TRUE(dhcp.remove_option(DHCPv6::PREFERENCE));

    PDU::serialization_type new_buffer = dhcp.serialize();
    EXPECT_EQ(old_buffer, new_buffer);
}
