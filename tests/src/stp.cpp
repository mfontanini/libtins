#include <gtest/gtest.h>
#include <cstring>
#include <string>
#include <stdint.h>
#include "stp.h"
#include "dot3.h"
#include "llc.h"

using namespace std;
using namespace Tins;

class STPTest : public testing::Test {
public:
    static const uint8_t expected_packet[];
    static void test_equals(const STP::bpdu_id_type& lhs, const STP::bpdu_id_type& rhs);
};

const uint8_t STPTest::expected_packet[] = { 
    146, 131, 138, 146, 146, 128, 0, 0, 144, 76, 8, 23, 181, 0, 146, 131, 
    120, 128, 0, 0, 144, 76, 8, 23, 181, 128, 1, 15, 0, 20, 0, 2, 0, 0, 
    0
};

void STPTest::test_equals(const STP::bpdu_id_type& lhs, const STP::bpdu_id_type& rhs) {
    EXPECT_EQ(lhs.priority, rhs.priority);
    EXPECT_EQ(lhs.ext_id, rhs.ext_id);
    EXPECT_EQ(lhs.id, rhs.id);
}

TEST_F(STPTest, DefaultConstructor) {
    STP pdu;
    EXPECT_EQ(0, pdu.proto_id());
    EXPECT_EQ(0, pdu.proto_version());
    EXPECT_EQ(0, pdu.bpdu_type());
    EXPECT_EQ(0, pdu.bpdu_flags());
    EXPECT_EQ(0U, pdu.root_path_cost());
    EXPECT_EQ(0, pdu.port_id());
    EXPECT_EQ(0, pdu.msg_age());
    EXPECT_EQ(0, pdu.max_age());
    EXPECT_EQ(0, pdu.hello_time());
    EXPECT_EQ(0, pdu.fwd_delay());
}

TEST_F(STPTest, ConstructorFromBuffer) {
    STP pdu(expected_packet, sizeof(expected_packet));
    STP::bpdu_id_type bpdu(0x8, 0, "00:90:4c:08:17:b5");
    EXPECT_EQ(0x9283, pdu.proto_id());
    EXPECT_EQ(0x8a, pdu.proto_version());
    EXPECT_EQ(0x92, pdu.bpdu_type());
    EXPECT_EQ(0x92, pdu.bpdu_flags());
    test_equals(bpdu, pdu.root_id());
    // root identifier(32768. 0, 00:90:4c:08:17:b5
    EXPECT_EQ(0x928378U, pdu.root_path_cost());
    test_equals(bpdu, pdu.bridge_id());
    // bridge identifier(32768. 0, 00:90:4c:08:17:b5
    EXPECT_EQ(0x8001, pdu.port_id());
    EXPECT_EQ(15, pdu.msg_age());
    EXPECT_EQ(20, pdu.max_age());
    EXPECT_EQ(2, pdu.hello_time());
    EXPECT_EQ(0, pdu.fwd_delay());
}

TEST_F(STPTest, BPDUId) {
    const uint8_t expected_packet[] = {
        0, 0, 0, 0, 0, 128, 100, 0, 28, 14, 135, 120, 0, 0, 0, 0, 4, 128, 
        100, 0, 28, 14, 135, 133, 0, 128, 4, 1, 0, 20, 0, 2, 0, 15, 0, 0, 
        0, 0, 0, 0, 0, 0, 0
    };
    STP pdu(expected_packet, sizeof(expected_packet));
    STP::bpdu_id_type bpdu(0x8, 100, "00:1c:0e:87:78:00");
    test_equals(bpdu, pdu.root_id());
}

TEST_F(STPTest, ChainedPDUs) {
    const uint8_t input[] = {
        1, 128, 194, 0, 0, 0, 0, 144, 76, 8, 23, 181, 0, 38, 66, 66, 3, 
        0, 0, 0, 0, 0, 128, 0, 0, 144, 76, 8, 23, 181, 0, 0, 0, 0, 128, 
        0, 0, 144, 76, 8, 23, 181, 128, 1, 0, 0, 20, 0, 2, 0, 0, 0
    };
    Dot3 pkt(input, sizeof(input));
    STP* stp = pkt.find_pdu<STP>();
    LLC* llc = pkt.find_pdu<LLC>();
    ASSERT_TRUE(stp != NULL);
    ASSERT_TRUE(llc != NULL);
    EXPECT_EQ(0x8001, stp->port_id());
    EXPECT_EQ(0, stp->msg_age());
    EXPECT_EQ(20, stp->max_age());
    EXPECT_EQ(2, stp->hello_time());
    llc->dsap(0);
    llc->ssap(0);
    EXPECT_EQ(
        PDU::serialization_type(input, input + sizeof(input)),
        pkt.serialize()
    );
}

TEST_F(STPTest, Serialize) {
    STP pdu(expected_packet, sizeof(expected_packet));
    EXPECT_EQ(
        PDU::serialization_type(expected_packet, expected_packet + sizeof(expected_packet)),
        pdu.serialize()
    );
}

TEST_F(STPTest, ProtoID) {
    STP pdu;
    pdu.proto_id(0x9283);
    EXPECT_EQ(0x9283, pdu.proto_id());
}

TEST_F(STPTest, ProtoVersion) {
    STP pdu;
    pdu.proto_version(0x15);
    EXPECT_EQ(0x15, pdu.proto_version());
}

TEST_F(STPTest, BPDUType) {
    STP pdu;
    pdu.bpdu_type(0x15);
    EXPECT_EQ(0x15, pdu.bpdu_type());
}

TEST_F(STPTest, BPDUFlags) {
    STP pdu;
    pdu.bpdu_flags(0x15);
    EXPECT_EQ(0x15, pdu.bpdu_flags());
}

TEST_F(STPTest, RootPathCost) {
    STP pdu;
    pdu.root_path_cost(0x28378462);
    EXPECT_EQ(0x28378462U, pdu.root_path_cost());
}

TEST_F(STPTest, PortID) {
    STP pdu;
    pdu.port_id(0x9283);
    EXPECT_EQ(0x9283, pdu.port_id());
}

TEST_F(STPTest, MsgAge) {
    STP pdu;
    pdu.msg_age(15);
    EXPECT_EQ(15, pdu.msg_age());
}

TEST_F(STPTest, MaxAge) {
    STP pdu;
    pdu.max_age(15);
    EXPECT_EQ(15, pdu.max_age());
}

TEST_F(STPTest, FwdDelay) {
    STP pdu;
    pdu.fwd_delay(15);
    EXPECT_EQ(15, pdu.fwd_delay());
}

TEST_F(STPTest, HelloTime) {
    STP pdu;
    pdu.hello_time(15);
    EXPECT_EQ(15, pdu.hello_time());
}

TEST_F(STPTest, RootID) {
    STP pdu;
    STP::bpdu_id_type bpdu(0x8, 100, "00:1c:0e:87:78:00");
    pdu.root_id(bpdu);
    test_equals(bpdu, pdu.root_id());
}

TEST_F(STPTest, BridgeID) {
    STP pdu;
    STP::bpdu_id_type bpdu(0x8, 100, "00:1c:0e:87:78:00");
    pdu.bridge_id(bpdu);
    test_equals(bpdu, pdu.bridge_id());
}
