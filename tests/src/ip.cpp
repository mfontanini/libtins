#include <gtest/gtest.h>
#include <cstring>
#include <string>
#include <stdint.h>
#include "ip.h"
#include "tcp.h"
#include "udp.h"
#include "icmp.h"
#include "ip_address.h"
#include "utils.h"
#include "ethernetII.h"

using namespace std;
using namespace Tins;

class IPTest : public testing::Test {
public:
    static const uint8_t expected_packet[], fragmented_packet[], fragmented_ether_ip_packet[];
    
    void test_equals(const IP &ip1, const IP &ip2);
};

const uint8_t IPTest::expected_packet[] = { 
    40, 127, 0, 32, 0, 122, 0, 67, 21, 1, 0, 0, 84, 52, 254, 5, 192, 
    168, 9, 43, 130, 11, 116, 106, 103, 171, 119, 171, 104, 101, 108, 0
};

const uint8_t IPTest::fragmented_packet[] = { 
    69, 0, 0, 60, 0, 242, 7, 223, 64, 17, 237, 220, 192, 0, 2, 1, 192, 
    0, 2, 2, 192, 0, 192, 0, 0, 40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

const uint8_t IPTest::fragmented_ether_ip_packet[] = {
    0, 10, 94, 83, 216, 229, 0, 21, 197, 50, 245, 6, 8, 0, 69, 0, 0, 60, 
    0, 242, 7, 223, 64, 17, 237, 220, 192, 0, 2, 1, 192, 0, 2, 2, 192, 0, 
    192, 0, 0, 40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};


TEST_F(IPTest, DefaultConstructor) {
    IP ip;
    EXPECT_EQ(ip.dst_addr(), "0.0.0.0");
    EXPECT_EQ(ip.src_addr(), "0.0.0.0");
    EXPECT_EQ(ip.version(), 4);
    EXPECT_EQ(ip.id(), 1);
    EXPECT_EQ(ip.pdu_type(), PDU::IP);
}

TEST_F(IPTest, CopyConstructor) {
    IP ip1(expected_packet, sizeof(expected_packet));
    IP ip2(ip1);
    test_equals(ip1, ip2);
}

TEST_F(IPTest, CopyAssignmentOperator) {
    IP ip1(expected_packet, sizeof(expected_packet));
    IP ip2;
    ip2 = ip1;
    test_equals(ip1, ip2);
}

TEST_F(IPTest, NestedCopy) {
    IP *nested = new IP(expected_packet, sizeof(expected_packet));
    IP ip1;
    ip1.inner_pdu(nested);
    IP ip2(ip1);
    test_equals(ip1, ip2);
}

TEST_F(IPTest, Constructor) {
    IP ip("192.168.0.1", "192.168.0.100");
    EXPECT_EQ(ip.dst_addr(), "192.168.0.1");
    EXPECT_EQ(ip.src_addr(), "192.168.0.100");
    EXPECT_EQ(ip.version(), 4);
    EXPECT_EQ(ip.id(), 1);
}

TEST_F(IPTest, ConstructorFromFragmentedPacket) {
    IP ip(fragmented_packet, sizeof(fragmented_packet));
    ASSERT_TRUE(ip.inner_pdu());
    EXPECT_EQ(PDU::RAW, ip.inner_pdu()->pdu_type());
}

TEST_F(IPTest, SerializeFragmentedPacket) {
    EthernetII pkt(fragmented_ether_ip_packet, sizeof(fragmented_ether_ip_packet));
    PDU::serialization_type buffer = pkt.serialize();
    EXPECT_EQ(
        PDU::serialization_type(
            fragmented_ether_ip_packet, 
            fragmented_ether_ip_packet + sizeof(fragmented_ether_ip_packet)
        ),
        buffer
    );
}

TEST_F(IPTest, TOS) {
    IP ip;
    ip.tos(0x7a);
    EXPECT_EQ(ip.tos(), 0x7a);
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
    ip.src_addr("192.155.32.10");
    EXPECT_EQ(ip.src_addr(), "192.155.32.10");
}

TEST_F(IPTest, DstIPInt) {
    IP ip;
    ip.dst_addr("192.155.32.10");
    EXPECT_EQ(ip.dst_addr(), "192.155.32.10");
}

TEST_F(IPTest, Version) {
    IP ip;
    ip.version(0xb);
    EXPECT_EQ(ip.version(), 0xb);
}

TEST_F(IPTest, SecOption) {
    IP ip;
    ip.security(IP::security_type(0x746a, 26539, 0x77ab, 0x68656c));
    IP::security_type found = ip.security();
    EXPECT_EQ(found.security, 0x746a);
    EXPECT_EQ(found.compartments, 26539);
    EXPECT_EQ(found.handling_restrictions, 0x77ab);
    EXPECT_EQ(found.transmission_control, 0x68656cU);
}

TEST_F(IPTest, LSRROption) {
    IP ip;
    IP::lsrr_type lsrr(0x2d);
    lsrr.routes.push_back("192.168.2.3");
    lsrr.routes.push_back("192.168.5.1");
    ip.lsrr(lsrr);
    IP::lsrr_type found = ip.lsrr();
    EXPECT_EQ(found.pointer, lsrr.pointer);
    EXPECT_EQ(found.routes, lsrr.routes);
}

TEST_F(IPTest, SSRROption) {
    IP ip;
    IP::ssrr_type ssrr(0x2d);
    ssrr.routes.push_back("192.168.2.3");
    ssrr.routes.push_back("192.168.5.1");
    ip.ssrr(ssrr);
    IP::ssrr_type found = ip.ssrr();
    EXPECT_EQ(found.pointer, ssrr.pointer);
    EXPECT_EQ(found.routes, ssrr.routes);
}

TEST_F(IPTest, RecordRouteOption) {
    IP ip;
    IP::record_route_type record_route(0x2d);
    record_route.routes.push_back("192.168.2.3");
    record_route.routes.push_back("192.168.5.1");
    ip.record_route(record_route);
    IP::record_route_type found = ip.record_route();
    EXPECT_EQ(found.pointer, record_route.pointer);
    EXPECT_EQ(found.routes, record_route.routes);
}

TEST_F(IPTest, StreamIDOption) {
    IP ip;
    ip.stream_identifier(0x91fa);
    EXPECT_EQ(0x91fa, ip.stream_identifier());
}

TEST_F(IPTest, AddOption) {
    IP ip;
    const uint8_t data[] = { 0x15, 0x17, 0x94, 0x66, 0xff };
    IP::option_identifier id(IP::SEC, IP::CONTROL, 1);
    ip.add_option(IP::option(id, data, data + sizeof(data)));
    const IP::option *opt;
    ASSERT_TRUE((opt = ip.search_option(id)));
    ASSERT_EQ(opt->data_size(), sizeof(data));
    EXPECT_TRUE(memcmp(opt->data_ptr(), data, sizeof(data)) == 0);
}

void IPTest::test_equals(const IP &ip1, const IP &ip2) {
    EXPECT_EQ(ip1.dst_addr(), ip2.dst_addr());
    EXPECT_EQ(ip1.src_addr(), ip2.src_addr());
    EXPECT_EQ(ip1.id(), ip2.id());
    EXPECT_EQ(ip1.frag_off(), ip2.frag_off());
    EXPECT_EQ(ip1.tos(), ip2.tos());
    EXPECT_EQ(ip1.ttl(), ip2.ttl());
    EXPECT_EQ(ip1.version(), ip2.version());
    EXPECT_EQ((bool)ip1.inner_pdu(), (bool)ip2.inner_pdu());
}

TEST_F(IPTest, ConstructorFromBuffer) {
    IP ip(expected_packet, sizeof(expected_packet));
    
    EXPECT_EQ(ip.dst_addr(), "192.168.9.43");
    EXPECT_EQ(ip.src_addr(), "84.52.254.5");
    EXPECT_EQ(ip.id(), 0x7a);
    EXPECT_EQ(ip.tos(), 0x7f);
    EXPECT_EQ(ip.frag_off(), 0x43);
    EXPECT_EQ(ip.protocol(), 1);
    EXPECT_EQ(ip.ttl(), 0x15);
    EXPECT_EQ(ip.version(), 2);
    
    IP::security_type sec = ip.security();
    EXPECT_EQ(sec.security, 0x746a);
    EXPECT_EQ(sec.compartments, 26539);
    EXPECT_EQ(sec.handling_restrictions, 0x77ab);
    EXPECT_EQ(sec.transmission_control, 0x68656cU);
}

TEST_F(IPTest, Serialize) {
    IP ip1(expected_packet, sizeof(expected_packet));
    PDU::serialization_type buffer = ip1.serialize();
    ASSERT_EQ(buffer.size(), sizeof(expected_packet));
    EXPECT_TRUE(std::equal(buffer.begin(), buffer.end(), expected_packet));
}

TEST_F(IPTest, StackedProtocols) {
    IP ip = IP() / TCP();
    IP::serialization_type buffer = ip.serialize();
    EXPECT_TRUE(IP(&buffer[0], buffer.size()).find_pdu<TCP>());
    
    ip = IP() / UDP();
    buffer = ip.serialize();
    EXPECT_TRUE(IP(&buffer[0], buffer.size()).find_pdu<UDP>());
    
    ip = IP() / ICMP();
    buffer = ip.serialize();
    EXPECT_TRUE(IP(&buffer[0], buffer.size()).find_pdu<ICMP>());
}

TEST_F(IPTest, SpoofedOptions) {
    IP pdu;
    uint8_t a[] = { 1,2,3,4,5,6 };
    pdu.add_option(
        IP::option(IP::NOOP, 250, a, a + sizeof(a))
    );
    pdu.add_option(
        IP::option(IP::NOOP, 250, a, a + sizeof(a))
    );
    pdu.add_option(
        IP::option(IP::NOOP, 250, a, a + sizeof(a))
    );
    // probably we'd expect it to crash if it's not working, valgrind plx
    EXPECT_EQ(3U, pdu.options().size());
    EXPECT_EQ(pdu.serialize().size(), pdu.size());
}
