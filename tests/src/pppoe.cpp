#include <gtest/gtest.h>
#include <cstring>
#include <string>
#include <stdint.h>
#include "pppoe.h"
#include "ethernetII.h"

using namespace std;
using namespace Tins;

class PPPoETest : public testing::Test {
public:
    static const uint8_t expected_packet[];
};

const uint8_t PPPoETest::expected_packet[] = {
    17, 9, 0, 0, 0, 16, 1, 1, 0, 0, 1, 2, 0, 0, 1, 3, 0, 4, 97, 98, 99, 100
};

TEST_F(PPPoETest, DefaultConstructor) {
    PPPoE pdu;
    EXPECT_EQ(1, pdu.version());
    EXPECT_EQ(1, pdu.type());
    EXPECT_EQ(0, pdu.code());
    EXPECT_EQ(0, pdu.session_id());
    EXPECT_EQ(0, pdu.payload_length());
}

TEST_F(PPPoETest, ConstructorFromBuffer) {
    PPPoE pdu(expected_packet, sizeof(expected_packet));
    EXPECT_EQ(1, pdu.version());
    EXPECT_EQ(1, pdu.type());
    EXPECT_EQ(0x09, pdu.code());
    EXPECT_EQ(0, pdu.session_id());
    EXPECT_EQ(16, pdu.payload_length());
    EXPECT_EQ(3U, pdu.tags().size());
    
    EXPECT_EQ("", pdu.service_name());
    ASSERT_TRUE(pdu.search_tag(PPPoE::SERVICE_NAME));
}

TEST_F(PPPoETest, StackedOnEthernet) {
    EthernetII eth = EthernetII() / PPPoE();
    PDU::serialization_type buffer = eth.serialize();
    EthernetII eth2(&buffer[0], buffer.size());
    ASSERT_TRUE(eth2.find_pdu<PPPoE>());
}

TEST_F(PPPoETest, StackedOnEthernetSerializationWithTags) {
    PPPoE pdu(expected_packet, sizeof(expected_packet));
    EthernetII eth = EthernetII() / pdu;
    PDU::serialization_type buffer = eth.serialize();
    EthernetII eth2(&buffer[0], buffer.size());
    PPPoE* unserialized = eth2.find_pdu<PPPoE>();
    ASSERT_TRUE(unserialized);
    EXPECT_EQ(
        PPPoE::serialization_type(expected_packet, expected_packet + sizeof(expected_packet)),
        unserialized->serialize()
    );

}

TEST_F(PPPoETest, Serialize) {
    PPPoE pdu(expected_packet, sizeof(expected_packet));
    PPPoE::serialization_type buffer = pdu.serialize();
    EXPECT_EQ(
        PPPoE::serialization_type(expected_packet, expected_packet + sizeof(expected_packet)),
        buffer
    );
}

TEST_F(PPPoETest, Version) {
    PPPoE pdu;
    pdu.version(6);
    EXPECT_EQ(6, pdu.version());
}

TEST_F(PPPoETest, Type) {
    PPPoE pdu;
    pdu.type(6);
    EXPECT_EQ(6, pdu.type());
}

TEST_F(PPPoETest, Code) {
    PPPoE pdu;
    pdu.code(0x7a);
    EXPECT_EQ(0x7a, pdu.code());
}

TEST_F(PPPoETest, SessionID) {
    PPPoE pdu;
    pdu.session_id(0x9182);
    EXPECT_EQ(0x9182, pdu.session_id());
}

TEST_F(PPPoETest, PayloadLength) {
    PPPoE pdu;
    pdu.payload_length(0x9182);
    EXPECT_EQ(0x9182, pdu.payload_length());
}

TEST_F(PPPoETest, ServiceName) {
    PPPoE pdu;
    pdu.service_name("carlos");
    EXPECT_EQ("carlos", pdu.service_name());
}

TEST_F(PPPoETest, ACName) {
    PPPoE pdu;
    pdu.ac_name("carlos");
    EXPECT_EQ("carlos", pdu.ac_name());
}

TEST_F(PPPoETest, HostUniq) {
    PPPoE pdu;
    uint8_t a[] = { 1,2,3,4,5,6 };
    byte_array data(a, a + sizeof(a));
    pdu.host_uniq(data);
    EXPECT_EQ(data, pdu.host_uniq());
}

TEST_F(PPPoETest, ACCookie) {
    PPPoE pdu;
    uint8_t a[] = { 1,2,3,4,5,6 };
    byte_array data(a, a + sizeof(a));
    pdu.ac_cookie(data);
    EXPECT_EQ(data, pdu.ac_cookie());
}

TEST_F(PPPoETest, VendorSpecific) {
    PPPoE pdu;
    uint8_t a[] = { 1,2,3,4,5,6 };
    PPPoE::vendor_spec_type output, data(
        0x9283f78,
        PPPoE::vendor_spec_type::data_type(a, a + sizeof(a))
    );
    pdu.vendor_specific(data);
    output = pdu.vendor_specific();
    EXPECT_EQ(data.data, output.data);
    EXPECT_EQ(data.vendor_id, output.vendor_id);
}

TEST_F(PPPoETest, RelaySessionID) {
    PPPoE pdu;
    uint8_t a[] = { 1,2,3,4,5,6 };
    byte_array data(a, a + sizeof(a));
    pdu.relay_session_id(data);
    EXPECT_EQ(data, pdu.relay_session_id());
}

TEST_F(PPPoETest, ServiceNameError) {
    {
        PPPoE pdu;
        pdu.service_name_error("carlos");
        EXPECT_EQ("carlos", pdu.service_name_error());
    }
    {
        PPPoE pdu;
        pdu.service_name_error("");
        EXPECT_EQ("", pdu.service_name_error());
    }
}

TEST_F(PPPoETest, ACSystemError) {
    PPPoE pdu;
    pdu.ac_system_error("carlos");
    EXPECT_EQ("carlos", pdu.ac_system_error());
}

TEST_F(PPPoETest, GenericError) {
    PPPoE pdu;
    pdu.generic_error("carlos");
    EXPECT_EQ("carlos", pdu.generic_error());
}

TEST_F(PPPoETest, SpoofedOptions) {
    PPPoE pdu;
    uint8_t a[] = { 1,2,3,4,5,6 };
    pdu.add_tag(
        PPPoE::tag(PPPoE::VENDOR_SPECIFIC, 65000, a, a + sizeof(a))
    );
    pdu.add_tag(
        PPPoE::tag(PPPoE::VENDOR_SPECIFIC, 65000, a, a + sizeof(a))
    );
    pdu.add_tag(
        PPPoE::tag(PPPoE::VENDOR_SPECIFIC, 65000, a, a + sizeof(a))
    );
    // probably we'd expect it to crash if it's not working, valgrind plx
    EXPECT_EQ(3U, pdu.tags().size());
    EXPECT_EQ(pdu.serialize().size(), pdu.size());
}
