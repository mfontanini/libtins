#include <gtest/gtest.h>
#include <cstring>
#include <string>
#include <stdint.h>
#include "icmp.h"
#include "ip.h"
#include "ethernetII.h"
#include "utils.h"

using namespace std;
using namespace Tins;

class ICMPTest : public testing::Test {
public:
    static const uint8_t expected_packets[][8];
    static const uint8_t ts_request[], ts_reply[];
    static const uint32_t expected_packet_count;
    
    void test_equals(const ICMP &icmp1, const ICMP &icmp2);
};

const uint8_t ICMPTest::expected_packets[][8] = {
    { 8, 1, 173, 123, 86, 209, 243, 177 },
    { 12, 0, 116, 255, 127, 0, 0, 0 }
};

const uint32_t ICMPTest::expected_packet_count = 1;

const uint8_t ICMPTest::ts_request[] = { 
    13, 0, 180, 60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 106, 97, 106, 97, 106
};

const uint8_t ICMPTest::ts_reply[] = { 
    14, 0, 172, 45, 0, 0, 0, 0, 0, 0, 0, 0, 4, 144, 30, 89, 4, 144, 30, 89, 0, 0, 0, 0, 0, 0
};


TEST_F(ICMPTest, DefaultConstructor) {
    ICMP icmp;
    EXPECT_EQ(icmp.code(), 0);
    EXPECT_EQ(icmp.type(), ICMP::ECHO_REQUEST);
    EXPECT_EQ(icmp.id(), 0);
    EXPECT_EQ(icmp.checksum(), 0);
}

TEST_F(ICMPTest, CopyConstructor) {
    ICMP icmp1(expected_packets[0], sizeof(expected_packets[0]));
    ICMP icmp2(icmp1);
    test_equals(icmp1, icmp2);
}

TEST_F(ICMPTest, CopyAssignmentOperator) {
    ICMP icmp1(expected_packets[0], sizeof(expected_packets[0]));
    ICMP icmp2;
    icmp2 = icmp1;
    test_equals(icmp1, icmp2);
}

TEST_F(ICMPTest, NestedCopy) {
    ICMP *nested = new ICMP(expected_packets[0], sizeof(expected_packets[0]));
    ICMP icmp1(expected_packets[0], sizeof(expected_packets[0]));
    icmp1.inner_pdu(nested);
    ICMP icmp2(icmp1);
    test_equals(icmp1, icmp2);
}

TEST_F(ICMPTest, FlagConstructor) {
    ICMP icmp(ICMP::ECHO_REPLY);
    EXPECT_EQ(icmp.type(), ICMP::ECHO_REPLY);
}

TEST_F(ICMPTest, ChecksumOnTimestamp) {
    const uint8_t raw_pkt[] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 69, 0, 0, 45, 0, 1, 0, 
        0, 128, 1, 185, 25, 192, 168, 0, 100, 192, 168, 0, 1, 13, 0, 237, 
        141, 0, 0, 0, 0, 159, 134, 1, 0, 151, 134, 1, 0, 152, 134, 1, 0, 
        98, 111, 105, 110, 103, 0
    };
    EthernetII pkt(raw_pkt, sizeof(raw_pkt));
    pkt.serialize();
    EXPECT_EQ(0xb919, pkt.rfind_pdu<IP>().checksum());
    EXPECT_EQ(0xed8d, pkt.rfind_pdu<ICMP>().checksum());
}

TEST_F(ICMPTest, AddressMaskRequest) {
    const uint8_t raw_pkt[] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 69, 0, 0, 32, 0, 1, 0, 
        0, 64, 1, 249, 38, 192, 168, 0, 100, 192, 168, 0, 1, 17, 0, 234, 
        249, 0, 0, 0, 0, 1, 2, 3, 4 
    };
    EthernetII pkt(raw_pkt, sizeof(raw_pkt));
    IP::serialization_type buffer = pkt.serialize();
    EXPECT_EQ(0xf926, pkt.rfind_pdu<IP>().checksum());
    EXPECT_EQ(0xeaf9, pkt.rfind_pdu<ICMP>().checksum());
    EXPECT_EQ(IPv4Address("1.2.3.4"), pkt.rfind_pdu<ICMP>().address_mask());
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

TEST_F(ICMPTest, Gateway) {
    ICMP icmp;
    icmp.gateway("1.2.3.4");
    EXPECT_EQ(IPv4Address("1.2.3.4"), icmp.gateway());
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

TEST_F(ICMPTest, OriginalTimestamp) {
    ICMP icmp;
    icmp.original_timestamp(0x1f8172da);
    EXPECT_EQ(0x1f8172da, icmp.original_timestamp());
}

TEST_F(ICMPTest, ReceiveTimestamp) {
    ICMP icmp;
    icmp.receive_timestamp(0x1f8172da);
    EXPECT_EQ(0x1f8172da, icmp.receive_timestamp());
}

TEST_F(ICMPTest, TransmitTimestamp) {
    ICMP icmp;
    icmp.transmit_timestamp(0x1f8172da);
    EXPECT_EQ(0x1f8172da, icmp.transmit_timestamp());
}

TEST_F(ICMPTest, AddressMask) {
    ICMP icmp;
    icmp.address_mask("192.168.0.1");
    EXPECT_EQ(IPv4Address("192.168.0.1"), icmp.address_mask());
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
    icmp.set_redirect(0x3d, "1.2.3.4");
    EXPECT_EQ(icmp.type(), ICMP::REDIRECT);
    EXPECT_EQ(0x3d, icmp.code());
    EXPECT_EQ(IPv4Address("1.2.3.4"), icmp.gateway());
}

void ICMPTest::test_equals(const ICMP &icmp1, const ICMP &icmp2) {
    EXPECT_EQ(icmp1.type(), icmp2.type());
    EXPECT_EQ(icmp1.code(), icmp2.code());
    EXPECT_EQ(icmp1.gateway(), icmp2.gateway());
    EXPECT_EQ(icmp1.id(), icmp2.id());
    EXPECT_EQ(icmp1.sequence(), icmp2.sequence());
    EXPECT_EQ(icmp1.pointer(), icmp2.pointer());
    EXPECT_EQ(icmp1.mtu(), icmp2.mtu());
    EXPECT_EQ((bool)icmp1.inner_pdu(), (bool)icmp2.inner_pdu());
}

TEST_F(ICMPTest, Serialize) {
    ICMP icmp1;
    icmp1.set_echo_request(0x34ab, 0x12f7);
    
    PDU::serialization_type buffer = icmp1.serialize();
    
    ICMP icmp2(icmp1);
    PDU::serialization_type buffer2 = icmp2.serialize();
    
    EXPECT_EQ(buffer, buffer2);
}

TEST_F(ICMPTest, TimestampMatchesResponse) {
    ICMP request(ts_request, sizeof(ts_request));
    EXPECT_TRUE(request.matches_response(ts_reply, sizeof(ts_reply)));
}

TEST_F(ICMPTest, ConstructorFromBuffer) {
    for(unsigned i(0); i < expected_packet_count; ++i) {
        ICMP icmp1(expected_packets[i], sizeof(expected_packets[i]));
        PDU::serialization_type buffer = icmp1.serialize();
        
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
        
        ICMP icmp2(&buffer[0], buffer.size());
        test_equals(icmp1, icmp2);
    }
}
