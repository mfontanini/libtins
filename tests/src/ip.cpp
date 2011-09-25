#include <gtest/gtest.h>
#include <cstring>
#include <string>
#include <stdint.h>
#include "ip.h"
#include "utils.h"

using namespace std;
using namespace Tins;

class IPTest : public testing::Test {
public:
    static const uint8_t expected_packet[];
    
    void test_equals(const IP &tcp1, const IP &tcp2);
};


TEST_F(IPTest, DefaultConstructor) {
    IP ip;
    EXPECT_EQ(ip.dst_addr(), 0);
    EXPECT_EQ(ip.src_addr(), 0);
    EXPECT_EQ(ip.version(), 4);
    EXPECT_EQ(ip.id(), 1);
    EXPECT_EQ(ip.pdu_type(), PDU::IP);
}

TEST_F(IPTest, IPIntConstructor) {
    IP ip(0x23abcdef, 0xff1443ab);
    EXPECT_EQ(ip.dst_addr(), 0x23abcdef);
    EXPECT_EQ(ip.src_addr(), 0xff1443ab);
    EXPECT_EQ(ip.version(), 4);
    EXPECT_EQ(ip.id(), 1);
}

TEST_F(IPTest, IPStringConstructor) {
    string ip1 = "154.33.200.55", ip2 = "192.10.11.52";
    IP ip(ip1, ip2);
    EXPECT_EQ(ip.dst_addr(), Utils::ip_to_int(ip1));
    EXPECT_EQ(ip.src_addr(), Utils::ip_to_int(ip2));
    EXPECT_EQ(ip.version(), 4);
    EXPECT_EQ(ip.id(), 1);
}

TEST_F(IPTest, HeadLen) {
    IP ip;
    ip.head_len(14);
    EXPECT_EQ(ip.head_len(), 14);
}

TEST_F(IPTest, TOS) {
    IP ip;
    ip.tos(0x7a);
    EXPECT_EQ(ip.tos(), 0x7a);
}

TEST_F(IPTest, TotLen) {
    IP ip;
    ip.tot_len(0x7f1a);
    EXPECT_EQ(ip.tot_len(), 0x7f1a);
}

TEST_F(IPTest, ID) {
    IP ip;
    ip.id(0x7f1a);
    EXPECT_EQ(ip.id(), 0x7f1a);
}

TEST_F(IPTest, FragOffset) {
    IP ip;
    ip.frag_off(0x7f1a);
    EXPECT_EQ(ip.frag_off(), 0x7f1a);
}

TEST_F(IPTest, TTL) {
    IP ip;
    ip.ttl(0x7f);
    EXPECT_EQ(ip.ttl(), 0x7f);
}

TEST_F(IPTest, Protocol) {
    IP ip;
    ip.protocol(0x7f);
    EXPECT_EQ(ip.protocol(), 0x7f);
}

TEST_F(IPTest, Check) {
    IP ip;
    ip.check(0x7f1a);
    EXPECT_EQ(ip.check(), 0x7f1a);
}

TEST_F(IPTest, SrcIPString) {
    IP ip;
    string string_ip("192.155.32.10");
    ip.src_addr(string_ip);
    EXPECT_EQ(ip.src_addr(), Utils::ip_to_int(string_ip));
}

TEST_F(IPTest, DstIPString) {
    IP ip;
    string string_ip("192.155.32.10");
    ip.dst_addr(string_ip);
    EXPECT_EQ(ip.dst_addr(), Utils::ip_to_int(string_ip));
}

TEST_F(IPTest, SrcIPInt) {
    IP ip;
    ip.src_addr(0x7f137ab3);
    EXPECT_EQ(ip.src_addr(), 0x7f137ab3);
}

TEST_F(IPTest, DstIPInt) {
    IP ip;
    ip.dst_addr(0x7f137ab3);
    EXPECT_EQ(ip.dst_addr(), 0x7f137ab3);
}

TEST_F(IPTest, Version) {
    IP ip;
    ip.version(0xb);
    EXPECT_EQ(ip.version(), 0xb);
}

TEST_F(IPTest, SecOption) {
    IP ip;
    const uint8_t data[] = { 0x15, 0x17, 0x94, 0x66, 0xff };
    ip.set_sec_option(data, sizeof(data));
    const IP::IPOption *option;
    ASSERT_TRUE((option = ip.search_option(IP::CONTROL, IP::SEC)));
    ASSERT_EQ(option->optional_data_size, sizeof(data));
    EXPECT_TRUE(memcmp(option->optional_data, data, sizeof(data)) == 0);
}
