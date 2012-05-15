#include <gtest/gtest.h>
#include <cstring>
#include <string>
#include <stdint.h>
#include <list>
#include <string>
#include "dhcp.h"
#include "utils.h"
#include "ethernetII.h"
#include "ipaddress.h"

using namespace std;
using namespace Tins;

class DHCPTest : public testing::Test {
public:
    static const uint8_t expected_packet[];
    static const uint8_t chaddr[], sname[], file[];
    static const IPv4Address addr;

    void test_equals(const DHCP &dhcp1, const DHCP &dhcp2);
    void test_option(const DHCP &dhcp, DHCP::Options opt, uint32_t len = 0, uint8_t *value = 0);
};

const uint8_t DHCPTest::chaddr[] = "\x16\xab\x54\x12\xfa\xca\x56\x7f\x1b\x65\x11\xfa\xda\xab\x19\x18";
const uint8_t DHCPTest::sname[] = "\x16\xab\x54\x12\xfa\xca\x56\x7f\x1b\x65\x11\xfa\xda\xbb\x19\x18"
                                  "\x16\xab\x54\x12\xfa\xca\x56\x7f\x1b\x65\x11\xfa\xda\xcb\x19\x18"
                                  "\x16\xab\x54\x12\xfa\xca\x56\x7f\x1b\x65\x11\xfa\xda\xeb\x19\x18"
                                  "\x16\xab\x54\x12\xfa\xca\x56\x7f\x1b\x65\x11\xfa\xda\xfb\x19\x18";
const uint8_t DHCPTest::file[] = "\x16\xab\x54\x12\xfa\xca\x56\x7f\x1b\x65\x11\xfa\xda\xbb\x19\x18"
                                  "\x16\xab\x54\x12\xfa\xca\x56\x7f\x1b\x65\x11\xfa\xda\xcb\x19\x18"
                                  "\x16\xab\x54\x12\xfa\xca\x56\x7f\x1b\x65\x11\xfa\xda\xeb\x19\x18"
                                  "\x16\xab\x54\x12\xfa\xca\x56\x7f\x1b\x65\x11\xfa\xda\xfb\x19\x18"
                                  "\x16\xab\x54\x12\xfa\xca\x56\x7f\x1b\x65\x11\xfa\xda\xbb\x19\x18"
                                  "\x16\xab\x54\x12\xfa\xca\x56\x7f\x1b\x65\x11\xfa\xda\xcb\x19\x18"
                                  "\x16\xab\x54\x12\xfa\xca\x56\x7f\x1b\x65\x11\xfa\xda\xeb\x19\x18"
                                  "\x16\xab\x54\x12\xfa\xca\x56\x7f\x1b\x65\x11\xfa\xda\xfb\x19\x18";
const IPv4Address DHCPTest::addr("192.168.8.1");

const uint8_t DHCPTest::expected_packet[] = {'\x01', '\x01', '\x06', '\x1f', '?', '\xab', '#', '\xde',
'\x9f', '\x1a', '\x00', '\x00', '\xc0', '\xa8', '\x00', 'f', '\xf3', '\x16', '"', 'b', '\xa7', ' ',
'\x0b', '\x9a', '{', '+', '7', '\xfe', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
'\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
'\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
'\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
'\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
'\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
'\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
'\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
'\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
'\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
'\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
'\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
'\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
'\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
'\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
'\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
'\x00', '\x00', '\x00', '\x00', '\x00', 'c', '\x82', 'S', 'c', '6', '\x04', '\xc0', '\xa8', '\x04', '\x02',
'\x01', '\x04', '\xff', '\xff', ' ', '\x0b', '5', '\x01', '\x04'};

TEST_F(DHCPTest, DefaultConstructor) {
    DHCP dhcp;
    EXPECT_EQ(dhcp.htype(), 1);
    EXPECT_EQ(dhcp.hlen(), EthernetII::ADDR_SIZE);
}

TEST_F(DHCPTest, OpCode) {
    DHCP dhcp;
    dhcp.opcode(0x71);
    EXPECT_EQ(dhcp.opcode(), 0x71);
}

TEST_F(DHCPTest, HType) {
    DHCP dhcp;
    dhcp.htype(0x71);
    EXPECT_EQ(dhcp.htype(), 0x71);
}

TEST_F(DHCPTest, HLen) {
    DHCP dhcp;
    dhcp.hlen(0x71);
    EXPECT_EQ(dhcp.hlen(), 0x71);
}

TEST_F(DHCPTest, HOps) {
    DHCP dhcp;
    dhcp.hops(0x71);
    EXPECT_EQ(dhcp.hops(), 0x71);
}

TEST_F(DHCPTest, Xid) {
    DHCP dhcp;
    dhcp.xid(0x71bd167c);
    EXPECT_EQ(dhcp.xid(), 0x71bd167c);
}

TEST_F(DHCPTest, Secs) {
    DHCP dhcp;
    dhcp.secs(0x71bd);
    EXPECT_EQ(dhcp.secs(), 0x71bd);
}

TEST_F(DHCPTest, Padding) {
    DHCP dhcp;
    dhcp.padding(0x71bd);
    EXPECT_EQ(dhcp.padding(), 0x71bd);
}

TEST_F(DHCPTest, Ciaddr) {
    DHCP dhcp;
    dhcp.ciaddr(addr);
    EXPECT_EQ(dhcp.ciaddr(), addr);
}

TEST_F(DHCPTest, Yiaddr) {
    DHCP dhcp;
    dhcp.yiaddr(addr);
    EXPECT_EQ(dhcp.yiaddr(), addr);
}

TEST_F(DHCPTest, Siaddr) {
    DHCP dhcp;
    dhcp.siaddr(addr);
    EXPECT_EQ(dhcp.siaddr(), addr);
}

TEST_F(DHCPTest, Giaddr) {
    DHCP dhcp;
    dhcp.giaddr(addr);
    EXPECT_EQ(dhcp.giaddr(), addr);
}

TEST_F(DHCPTest, Chaddr) {
    DHCP dhcp;
    dhcp.chaddr(chaddr);
    EXPECT_TRUE(memcmp(dhcp.chaddr(), chaddr, dhcp.hlen()) == 0);
}

TEST_F(DHCPTest, Sname) {
    DHCP dhcp;
    dhcp.sname(sname);
    EXPECT_TRUE(memcmp(dhcp.sname(), sname, 64) == 0);
}

TEST_F(DHCPTest, File) {
    DHCP dhcp;
    dhcp.file(file);
    EXPECT_TRUE(memcmp(dhcp.file(), file, 128) == 0);
}

void DHCPTest::test_option(const DHCP &dhcp, DHCP::Options opt, uint32_t len, uint8_t *value) {
    const DHCP::DHCPOption *option = dhcp.search_option(opt);
    ASSERT_TRUE(option != 0);
    EXPECT_EQ(option->option, opt);
    EXPECT_EQ(option->length, len);
    if(len)
        EXPECT_TRUE(memcmp(option->value, value, len) == 0);
}

TEST_F(DHCPTest, TypeOption) {
    DHCP dhcp;
    uint8_t value = DHCP::REQUEST, value_found;
    dhcp.add_type_option((DHCP::Flags)value);
    ASSERT_TRUE(dhcp.search_type_option(&value_found));
    EXPECT_EQ(value, value_found);
}

TEST_F(DHCPTest, ServerIdentifierOption) {
    DHCP dhcp;
    uint32_t ip = 0xf3ba34f1, ip_found;
    dhcp.add_server_identifier(ip);
    ASSERT_TRUE(dhcp.search_server_identifier(&ip_found));
    EXPECT_EQ(ip, ip_found);
}

TEST_F(DHCPTest, LeaseTimeOption) {
    DHCP dhcp;
    uint32_t ltime = 0x34f1, ltime_found;
    dhcp.add_lease_time(ltime);
    ASSERT_TRUE(dhcp.search_lease_time(&ltime_found));
    EXPECT_EQ(ltime, ltime_found);
}

TEST_F(DHCPTest, SubnetMaskOption) {
    DHCP dhcp;
    uint32_t ip = 0xf3ba34f1, ip_found;
    dhcp.add_subnet_mask(ip);
    ASSERT_TRUE(dhcp.search_subnet_mask(&ip_found));
    EXPECT_EQ(ip, ip_found);
}

TEST_F(DHCPTest, RoutersOption) {
    DHCP dhcp;
    list<uint32_t> routers;
    routers.push_back(Utils::ip_to_int("192.168.0.253"));
    routers.push_back(Utils::ip_to_int("10.123.45.67"));
    dhcp.add_routers_option(routers);

    list<uint32_t> routers2;
    ASSERT_TRUE(dhcp.search_routers_option(&routers2));
    ASSERT_EQ(routers.size(), routers2.size());
    while(routers.size()) {
        EXPECT_EQ(routers.front(), routers2.front());
        routers.pop_front();
        routers2.pop_front();
    }
}

TEST_F(DHCPTest, DNSOption) {
    DHCP dhcp;
    list<uint32_t> dns;
    dns.push_back(Utils::ip_to_int("192.168.0.253"));
    dns.push_back(Utils::ip_to_int("10.123.45.67"));
    dhcp.add_dns_option(dns);

    list<uint32_t> dns2;
    ASSERT_TRUE(dhcp.search_dns_option(&dns2));
    ASSERT_EQ(dns.size(), dns2.size());
    while(dns.size()) {
        EXPECT_EQ(dns.front(), dns2.front());
        dns.pop_front();
        dns2.pop_front();
    }
}

TEST_F(DHCPTest, DomainNameOption) {
    DHCP dhcp;
    string domain = "libtins.test.domain", domain_found;
    dhcp.add_domain_name(domain);
    ASSERT_TRUE(dhcp.search_domain_name(&domain_found));
    EXPECT_TRUE(domain == domain_found);
}

TEST_F(DHCPTest, BroadcastOption) {
    DHCP dhcp;
    uint32_t ip = 0xf3ba34f1, ip_found;
    dhcp.add_broadcast_option(ip);
    ASSERT_TRUE(dhcp.search_broadcast_option(&ip_found));
    EXPECT_EQ(ip, ip_found);
}

void DHCPTest::test_equals(const DHCP &dhcp1, const DHCP &dhcp2) {
    EXPECT_EQ(dhcp1.opcode(), dhcp2.opcode());
    EXPECT_EQ(dhcp1.htype(), dhcp2.htype());
    ASSERT_EQ(dhcp1.hlen(), dhcp2.hlen());
    EXPECT_EQ(dhcp1.hops(), dhcp2.hops());
    EXPECT_EQ(dhcp1.xid(), dhcp2.xid());
    EXPECT_EQ(dhcp1.padding(), dhcp2.padding());
    EXPECT_EQ(dhcp1.ciaddr(), dhcp2.ciaddr());
    EXPECT_EQ(dhcp1.yiaddr(), dhcp2.yiaddr());
    EXPECT_EQ(dhcp1.siaddr(), dhcp2.siaddr());
    EXPECT_EQ(dhcp1.giaddr(), dhcp2.giaddr());
    EXPECT_TRUE(memcmp(dhcp1.chaddr(), dhcp2.chaddr(), dhcp1.hlen()) == 0);
    EXPECT_TRUE(memcmp(dhcp1.sname(), dhcp2.sname(), 64) == 0);
    EXPECT_TRUE(memcmp(dhcp1.file(), dhcp2.file(), 128) == 0);
    const std::list<DHCP::DHCPOption> options1(dhcp1.options());
    const std::list<DHCP::DHCPOption> options2(dhcp2.options());
    ASSERT_EQ(options1.size(), options2.size());
    std::list<DHCP::DHCPOption>::const_iterator it1, it2;
    it1 = options1.begin();
    it2 = options2.begin();
    while(it1 != options1.end()) {
        EXPECT_EQ(it1->option, it2->option);
        ASSERT_EQ(it1->length, it2->length);
        EXPECT_TRUE(memcmp(it1->value, it2->value, it1->length) == 0);
        it1++; it2++;
    }
}

TEST_F(DHCPTest, ConstructorFromBuffer) {
    DHCP dhcp1(expected_packet, sizeof(expected_packet));
    uint32_t ip;

    EXPECT_EQ(dhcp1.opcode(), DHCP::DISCOVER);
    EXPECT_EQ(dhcp1.htype(), 1);
    ASSERT_EQ(dhcp1.hlen(), EthernetII::ADDR_SIZE);
    EXPECT_EQ(dhcp1.hops(), 0x1f);
    EXPECT_EQ(dhcp1.xid(), 0x3fab23de);
    EXPECT_EQ(dhcp1.secs(), 0x9f1a);
    EXPECT_EQ(dhcp1.padding(), 0);
    EXPECT_EQ(dhcp1.ciaddr(), Utils::ip_to_int("192.168.0.102"));
    EXPECT_EQ(dhcp1.yiaddr(), Utils::ip_to_int("243.22.34.98"));
    EXPECT_EQ(dhcp1.giaddr(), Utils::ip_to_int("123.43.55.254"));
    EXPECT_EQ(dhcp1.siaddr(), Utils::ip_to_int("167.32.11.154"));
    ASSERT_TRUE(dhcp1.search_server_identifier(&ip));
    EXPECT_EQ(ip, Utils::net_to_host_l(Utils::ip_to_int("192.168.4.2")));

    uint32_t size;
    uint8_t *buffer = dhcp1.serialize(size);

    DHCP dhcp2(buffer, size);
    test_equals(dhcp1, dhcp2);
    delete[] buffer;
}


