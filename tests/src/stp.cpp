#include <gtest/gtest.h>
#include <cstring>
#include <string>
#include <stdint.h>
#include "stp.h"

using namespace std;
using namespace Tins;

class STPTest : public testing::Test {
public:
    static const uint8_t expected_packet[];
};

const uint8_t STPTest::expected_packet[] = { 
    146, 131, 138, 146, 146, 128, 0, 0, 144, 76, 8, 23, 181, 0, 146, 131, 
    120, 128, 0, 0, 144, 76, 8, 23, 181, 128, 1, 15, 0, 20, 0, 2, 0, 0, 
    0, 165, 165, 165, 165, 165, 165, 165, 165
};

TEST_F(STPTest, DefaultConstructor) {
    STP pdu;
    EXPECT_EQ(0, pdu.proto_id());
    EXPECT_EQ(0, pdu.proto_version());
    EXPECT_EQ(0, pdu.bpdu_type());
    EXPECT_EQ(0, pdu.bpdu_flags());
    EXPECT_EQ(0, pdu.root_path_cost());
    EXPECT_EQ(0, pdu.port_id());
    EXPECT_EQ(0, pdu.msg_age());
    EXPECT_EQ(0, pdu.max_age());
    EXPECT_EQ(0, pdu.hello_time());
    EXPECT_EQ(0, pdu.fwd_delay());
}

TEST_F(STPTest, ConstructorFromBuffer) {
    STP pdu(expected_packet, sizeof(expected_packet));
    EXPECT_EQ(0x9283, pdu.proto_id());
    EXPECT_EQ(0x8a, pdu.proto_version());
    EXPECT_EQ(0x92, pdu.bpdu_type());
    EXPECT_EQ(0x92, pdu.bpdu_flags());
    // root identifier(32768. 0, 00:90:4c:08:17:b5
    EXPECT_EQ(0x928378, pdu.root_path_cost());
    // bridge identifier(32768. 0, 00:90:4c:08:17:b5
    EXPECT_EQ(0x8001, pdu.port_id());
    EXPECT_EQ(15, pdu.msg_age());
    EXPECT_EQ(20, pdu.max_age());
    EXPECT_EQ(2, pdu.hello_time());
    EXPECT_EQ(0, pdu.fwd_delay());
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
    EXPECT_EQ(0x28378462, pdu.root_path_cost());
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
