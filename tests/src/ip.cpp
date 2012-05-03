#include <gtest/gtest.h>
#include <cstring>
#include <string>
#include <stdint.h>
#include "ip.h"
#include "ipaddress.h"
#include "utils.h"

using namespace std;
using namespace Tins;

class IPTest : public testing::Test {
public:
    static const uint8_t expected_packet[];
    
    void test_equals(const IP &ip1, const IP &ip2);
};

const uint8_t IPTest::expected_packet[] = { '(', '\x7f', '\x00', ' ', 
'\x00', 'z', '\x00', 'C', '\x15', '\x01', '\xfb', 'g', 'T', '4', '\xfe', 
'\x05', '\xc0', '\xa8', '\t', '+', '\x82', '\x0b', 't', 'j', 'g', '\xab', 
'w', '\xab', 'h', 'e', 'l', '\x00' };


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
    EXPECT_EQ(ip.dst_addr(), IPv4Address(0x23abcdef));
    EXPECT_EQ(ip.src_addr(), IPv4Address(0xff1443ab));
    EXPECT_EQ(ip.version(), 4);
    EXPECT_EQ(ip.id(), 1);
}

TEST_F(IPTest, IPStringConstructor) {
    string ip1 = "154.33.200.55", ip2 = "192.10.11.52";
    IP ip(ip1, ip2);
    EXPECT_EQ(ip.dst_addr(), IPv4Address(ip1));
    EXPECT_EQ(ip.src_addr(), IPv4Address(ip2));
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
    EXPECT_EQ(ip.src_addr(), IPv4Address(string_ip));
}

TEST_F(IPTest, DstIPString) {
    IP ip;
    string string_ip("192.155.32.10");
    ip.dst_addr(string_ip);
    EXPECT_EQ(ip.dst_addr(), IPv4Address(string_ip));
}

TEST_F(IPTest, SrcIPInt) {
    IP ip;
    ip.src_addr(0x7f137ab3);
    EXPECT_EQ(ip.src_addr(), IPv4Address(0x7f137ab3));
}

TEST_F(IPTest, DstIPInt) {
    IP ip;
    ip.dst_addr(0x7f137ab3);
    EXPECT_EQ(ip.dst_addr(), IPv4Address(0x7f137ab3));
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
    ASSERT_EQ(option->data_size(), sizeof(data));
    EXPECT_TRUE(memcmp(option->data_ptr(), data, sizeof(data)) == 0);
}

void IPTest::test_equals(const IP &ip1, const IP &ip2) {
    EXPECT_EQ(ip1.dst_addr(), ip2.dst_addr());
    EXPECT_EQ(ip1.src_addr(), ip2.src_addr());
    EXPECT_EQ(ip1.id(), ip2.id());
    EXPECT_EQ(ip1.frag_off(), ip2.frag_off());
    EXPECT_EQ(ip1.tos(), ip2.tos());
    EXPECT_EQ(ip1.ttl(), ip2.ttl());
    EXPECT_EQ(ip1.version(), ip2.version());
}

TEST_F(IPTest, ConstructorFromBuffer) {
    IP ip1(expected_packet, sizeof(expected_packet));
    const uint8_t opt_sec[] = { 't', 'j', 'g', '\xab', 'w', '\xab', 'h', 'e', 'l' };
    
    EXPECT_EQ(ip1.dst_addr(), IPv4Address ("192.168.9.43"));
    EXPECT_EQ(ip1.src_addr(), IPv4Address("84.52.254.5"));
    EXPECT_EQ(ip1.id(), 0x7a);
    EXPECT_EQ(ip1.tos(), 0x7f);
    EXPECT_EQ(ip1.frag_off(), 0x43);
    EXPECT_EQ(ip1.protocol(), 1);
    EXPECT_EQ(ip1.ttl(), 0x15);
    EXPECT_EQ(ip1.version(), 2);
    const IP::IPOption *option;
    ASSERT_TRUE((option = ip1.search_option(IP::CONTROL, IP::SEC)));
    EXPECT_EQ(option->type.number, IP::SEC);
    EXPECT_EQ(option->type.op_class, IP::CONTROL);
    ASSERT_EQ(option->data_size(), sizeof(opt_sec));
    EXPECT_TRUE(memcmp(option->data_ptr(), opt_sec, sizeof(opt_sec)) == 0);
    
    uint32_t size;
    uint8_t *buffer = ip1.serialize(size);
    ASSERT_TRUE(buffer);
    
    IP ip2(buffer, size);
}
