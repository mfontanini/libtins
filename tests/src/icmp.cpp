#include <gtest/gtest.h>
#include <cstring>
#include <string>
#include <stdint.h>
#include "icmp.h"
#include "utils.h"

using namespace std;
using namespace Tins;

class ICMPTest : public testing::Test {
public:
    static const uint8_t expected_packets[][8];
    static const uint32_t expected_packet_count;
    
    void test_equals(const ICMP &icmp1, const ICMP &icmp2);
};

const uint8_t ICMPTest::expected_packets[][8] = {
    {'\x08', '\x01', '\xad', '{', 'V', '\xd1', '\xf3', '\xb1' },
    {'\x0c', '\x00', 't', '\xff', '\x7f', '\x00', '\x00', '\x00'}
};
const uint32_t ICMPTest::expected_packet_count = 1;


TEST_F(ICMPTest, DefaultConstructor) {
    ICMP icmp;
    EXPECT_EQ(icmp.code(), 0);
    EXPECT_EQ(icmp.type(), ICMP::ECHO_REQUEST);
    EXPECT_EQ(icmp.id(), 0);
    EXPECT_EQ(icmp.check(), 0);
    EXPECT_EQ(icmp.gateway(), 0);
    EXPECT_EQ(icmp.mtu(), 0);
}

TEST_F(ICMPTest, FlagConstructor) {
    ICMP icmp(ICMP::ECHO_REPLY);
    EXPECT_EQ(icmp.type(), ICMP::ECHO_REPLY);
}

TEST_F(ICMPTest, Code) {
    ICMP icmp;
    icmp.code(0x7a);
    EXPECT_EQ(icmp.code(), 0x7a);
}

TEST_F(ICMPTest, Id) {
    ICMP icmp;
    icmp.id(0x7af1);
    EXPECT_EQ(icmp.id(), 0x7af1);
}

TEST_F(ICMPTest, Sequence) {
    ICMP icmp;
    icmp.sequence(0x7af1);
    EXPECT_EQ(icmp.sequence(), 0x7af1);
}

TEST_F(ICMPTest, Type) {
    ICMP icmp;
    icmp.type(ICMP::ECHO_REPLY);
    EXPECT_EQ(icmp.type(), ICMP::ECHO_REPLY);
}

TEST_F(ICMPTest, Checksum) {
    ICMP icmp;
    icmp.check(0x31fd);
    EXPECT_EQ(icmp.check(), 0x31fd);
}

TEST_F(ICMPTest, Gateway) {
    ICMP icmp;
    icmp.gateway(0x31fdb5cd);
    EXPECT_EQ(icmp.gateway(), 0x31fdb5cd);
}

TEST_F(ICMPTest, MTU) {
    ICMP icmp;
    icmp.mtu(0x7af1);
    EXPECT_EQ(icmp.mtu(), 0x7af1);
}

TEST_F(ICMPTest, Pointer) {
    ICMP icmp;
    icmp.pointer(0xf1);
    EXPECT_EQ(icmp.pointer(), 0xf1);
}

TEST_F(ICMPTest, SetEchoRequest) {
    ICMP icmp;
    icmp.set_echo_request(0x7af1, 0x123f);
    EXPECT_EQ(icmp.type(), ICMP::ECHO_REQUEST);
    EXPECT_EQ(icmp.id(), 0x7af1);
    EXPECT_EQ(icmp.sequence(), 0x123f);
}

TEST_F(ICMPTest, SetEchoReply) {
    ICMP icmp;
    icmp.set_echo_reply(0x7af1, 0x123f);
    EXPECT_EQ(icmp.type(), ICMP::ECHO_REPLY);
    EXPECT_EQ(icmp.id(), 0x7af1);
    EXPECT_EQ(icmp.sequence(), 0x123f);
}

TEST_F(ICMPTest, SetInfoRequest) {
    ICMP icmp;
    icmp.set_info_request(0x7af1, 0x123f);
    EXPECT_EQ(icmp.type(), ICMP::INFO_REQUEST);
    EXPECT_EQ(icmp.id(), 0x7af1);
    EXPECT_EQ(icmp.sequence(), 0x123f);
}

TEST_F(ICMPTest, SetInfoReply) {
    ICMP icmp;
    icmp.set_info_reply(0x7af1, 0x123f);
    EXPECT_EQ(icmp.type(), ICMP::INFO_REPLY);
    EXPECT_EQ(icmp.id(), 0x7af1);
    EXPECT_EQ(icmp.sequence(), 0x123f);
}

TEST_F(ICMPTest, SetDestinationUnreachable) {
    ICMP icmp;
    icmp.set_dest_unreachable();
    EXPECT_EQ(icmp.type(), ICMP::DEST_UNREACHABLE);
}

TEST_F(ICMPTest, SetTimeExceeded) {
    ICMP icmp;
    icmp.set_time_exceeded(true);
    EXPECT_EQ(icmp.type(), ICMP::TIME_EXCEEDED);
    EXPECT_EQ(icmp.code(), 0);
    icmp.set_time_exceeded(false);
    EXPECT_EQ(icmp.type(), ICMP::TIME_EXCEEDED);
    EXPECT_EQ(icmp.code(), 1);
}

TEST_F(ICMPTest, SetParamProblem) {
    ICMP icmp;
    icmp.set_param_problem(true, 0x4f);
    EXPECT_EQ(icmp.type(), ICMP::PARAM_PROBLEM);
    EXPECT_EQ(icmp.code(), 0);
    EXPECT_EQ(icmp.pointer(), 0x4f);
    
    icmp.set_param_problem(false);
    EXPECT_EQ(icmp.type(), ICMP::PARAM_PROBLEM);
    EXPECT_EQ(icmp.code(), 1);
}

TEST_F(ICMPTest, SetSourceQuench) {
    ICMP icmp;
    icmp.set_source_quench();
    EXPECT_EQ(icmp.type(), ICMP::SOURCE_QUENCH);
}

TEST_F(ICMPTest, SetRedirect) {
    ICMP icmp;
    icmp.set_redirect(0x3d, 0xf1dc);
    EXPECT_EQ(icmp.type(), ICMP::REDIRECT);
    EXPECT_EQ(icmp.code(), 0x3d);
    EXPECT_EQ(icmp.gateway(), 0xf1dc);
}

void ICMPTest::test_equals(const ICMP &icmp1, const ICMP &icmp2) {
    EXPECT_EQ(icmp1.type(), icmp2.type());
    EXPECT_EQ(icmp1.code(), icmp2.code());
    EXPECT_EQ(icmp1.gateway(), icmp2.gateway());
    EXPECT_EQ(icmp1.id(), icmp2.id());
    EXPECT_EQ(icmp1.sequence(), icmp2.sequence());
    EXPECT_EQ(icmp1.pointer(), icmp2.pointer());
    EXPECT_EQ(icmp1.mtu(), icmp2.mtu());
}

TEST_F(ICMPTest, ClonePDU) {
    ICMP icmp1;
    icmp1.set_echo_request(0x34ab, 0x12f7);
    
    ICMP *icmp2 = static_cast<ICMP*>(icmp1.clone_pdu());
    test_equals(icmp1, *icmp2);
    delete icmp2;
}

TEST_F(ICMPTest, Serialize) {
    ICMP icmp1;
    icmp1.set_echo_request(0x34ab, 0x12f7);
    
    uint32_t size;
    uint8_t *buffer = icmp1.serialize(size);
    ASSERT_TRUE(buffer);
    
    ICMP icmp2(icmp1);
    uint32_t size2;
    uint8_t *buffer2 = icmp2.serialize(size2);
    ASSERT_EQ(size, size2);
    EXPECT_TRUE(memcmp(buffer, buffer2, size) == 0);
    delete[] buffer;
    delete[] buffer2;
}

TEST_F(ICMPTest, ConstructorFromBuffer) {
    for(unsigned i(0); i < expected_packet_count; ++i) {
        ICMP icmp1(expected_packets[i], sizeof(expected_packets[i]));
        uint32_t size;
        uint8_t *buffer = icmp1.serialize(size);
        
        switch(i) {
            case 0:
                EXPECT_EQ(icmp1.type(), ICMP::ECHO_REQUEST);
                EXPECT_EQ(icmp1.code(), 1);
                EXPECT_EQ(icmp1.id(), 0x56d1);
                EXPECT_EQ(icmp1.sequence(), 0xf3b1);
                break;
            case 1:
                EXPECT_EQ(icmp1.type(), ICMP::PARAM_PROBLEM);
                EXPECT_EQ(icmp1.code(), 0);
                EXPECT_EQ(icmp1.pointer(), 0x7f);
                break;
        }
        
        ICMP icmp2(buffer, size);
        test_equals(icmp1, icmp2);
        
        delete[] buffer;
    }
}
