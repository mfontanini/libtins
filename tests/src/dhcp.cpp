#include <gtest/gtest.h>
#include <cstring>
#include <string>
#include <stdint.h>
#include <list>
#include <string>
#include "dhcp.h"
#include "utils.h"
#include "ethernetII.h"
#include "hw_address.h"
#include "ip_address.h"

using namespace std;
using namespace Tins;

class DHCPTest : public testing::Test {
public:
    static const uint8_t expected_packet[];
    static const BootP::chaddr_type chaddr;
    static const uint8_t sname[], file[];
    static const IPv4Address addr;

    void test_equals(const DHCP& dhcp1, const DHCP& dhcp2);
    void test_option(const DHCP& dhcp, DHCP::OptionTypes opt, uint32_t len = 0, uint8_t* value = 0);
};

const BootP::chaddr_type DHCPTest::chaddr("16:ab:54:12:fa:ca:56:7f:1b:65:11:fa:da:ab:19:18");
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

const uint8_t DHCPTest::expected_packet[] = {
    1, 1, 6, 31, 63, 171, 35, 222, 159, 26, 0, 0, 192, 168, 0, 102, 243, 
    22, 34, 98, 167, 32, 11, 154, 123, 43, 55, 254, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99, 130, 83, 99, 
    54, 4, 192, 168, 4, 2, 1, 4, 255, 255, 32, 11, 53, 1, 4, 3, 8, 192, 
    168, 0, 1, 127, 0, 0, 1, 6, 8, 192, 168, 0, 2, 127, 0, 0, 1
};

TEST_F(DHCPTest, DefaultConstructor) {
    DHCP dhcp;
    EXPECT_EQ(dhcp.htype(), 1);
    EXPECT_EQ(dhcp.hlen(), (const size_t)EthernetII::address_type::address_size);
}

TEST_F(DHCPTest, CopyConstructor) {
    DHCP dhcp1(expected_packet, sizeof(expected_packet));
    DHCP dhcp2(dhcp1);
    test_equals(dhcp1, dhcp2);
}

TEST_F(DHCPTest, CopyAssignmentOperator) {
    DHCP dhcp1(expected_packet, sizeof(expected_packet));
    DHCP dhcp2 = dhcp1;
    test_equals(dhcp1, dhcp2);
}

TEST_F(DHCPTest, NestedCopy) {
    
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
    EXPECT_EQ(dhcp.xid(), 0x71bd167cU);
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
    EXPECT_EQ(dhcp.chaddr(), chaddr);
    
    HWAddress<4> hwaddr("31:33:70:00");
    dhcp.chaddr(hwaddr);
    HWAddress<4> copied(dhcp.chaddr());
    EXPECT_EQ(copied, hwaddr);
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

void DHCPTest::test_option(const DHCP& dhcp, DHCP::OptionTypes opt, uint32_t len, uint8_t* value) {
    const DHCP::option* option = dhcp.search_option(opt);
    ASSERT_TRUE(option != 0);
    EXPECT_EQ(option->option(), opt);
    ASSERT_EQ(option->data_size(), len);
    EXPECT_TRUE(std::equal(option->data_ptr(), option->data_ptr() + option->data_size(), value));
}

TEST_F(DHCPTest, TypeOption) {
    DHCP dhcp;
    dhcp.type(DHCP::REQUEST);
    EXPECT_EQ(dhcp.type(), DHCP::REQUEST);
}

TEST_F(DHCPTest, ServerIdentifierOption) {
    DHCP dhcp;
    dhcp.server_identifier("192.168.0.1");
    EXPECT_EQ(DHCP::ipaddress_type("192.168.0.1"), dhcp.server_identifier());
}

TEST_F(DHCPTest, LeaseTimeOption) {
    DHCP dhcp;
    uint32_t ltime = 0x34f1;
    dhcp.lease_time(ltime);
    EXPECT_EQ(ltime, dhcp.lease_time());
}

TEST_F(DHCPTest, SubnetMaskOption) {
    DHCP dhcp;
    IPv4Address ip = "192.168.0.1", ip_found;
    dhcp.subnet_mask(ip);
    EXPECT_EQ(ip, dhcp.subnet_mask());
}

TEST_F(DHCPTest, RoutersOption) {
    DHCP dhcp;
    std::vector<IPv4Address> routers;
    routers.push_back("192.168.0.253");
    routers.push_back("10.123.45.67");
    dhcp.routers(routers);

    std::vector<IPv4Address> routers2 = dhcp.routers();
    EXPECT_EQ(routers, routers2);
}

TEST_F(DHCPTest, DNSOption) {
    DHCP dhcp;
    std::vector<IPv4Address> dns;
    dns.push_back("192.168.0.253");
    dns.push_back("10.123.45.67");
    dhcp.domain_name_servers(dns);

    std::vector<IPv4Address> dns2 = dhcp.domain_name_servers();
    EXPECT_EQ(dns, dns2);
}

TEST_F(DHCPTest, DomainNameOption) {
    DHCP dhcp;
    string domain = "libtins.test.domain";
    dhcp.domain_name(domain);
    EXPECT_EQ(domain, dhcp.domain_name());
}

TEST_F(DHCPTest, HostnameOption) {
    DHCP dhcp;
    string hostname = "libtins-hostname";
    dhcp.hostname(hostname);
    EXPECT_EQ(hostname, dhcp.hostname());
}

TEST_F(DHCPTest, BroadcastOption) {
    DHCP dhcp;
    IPv4Address ip = "192.168.0.1", ip_found;
    dhcp.broadcast(ip);
    EXPECT_EQ(ip, dhcp.broadcast());
}

void DHCPTest::test_equals(const DHCP& dhcp1, const DHCP& dhcp2) {
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
    EXPECT_EQ(dhcp1.chaddr(), dhcp2.chaddr());
    EXPECT_TRUE(memcmp(dhcp1.sname(), dhcp2.sname(), 64) == 0);
    EXPECT_TRUE(memcmp(dhcp1.file(), dhcp2.file(), 128) == 0);
    const DHCP::options_type options1(dhcp1.options());
    const DHCP::options_type options2(dhcp2.options());
    ASSERT_EQ(options1.size(), options2.size());
    DHCP::options_type::const_iterator it1, it2;
    it1 = options1.begin();
    it2 = options2.begin();
    while(it1 != options1.end()) {
        EXPECT_EQ(it1->option(), it2->option());
        ASSERT_EQ(it1->data_size(), it2->data_size());
        EXPECT_TRUE(std::equal(it1->data_ptr(), it1->data_ptr() + it1->data_size(), it2->data_ptr()));
        it1++; it2++;
    }
}

TEST_F(DHCPTest, ConstructorFromBuffer) {
    DHCP dhcp1(expected_packet, sizeof(expected_packet));
    std::vector<IPv4Address> routers, expected_routers;
    expected_routers.push_back("192.168.0.1");
    expected_routers.push_back("127.0.0.1");

    EXPECT_EQ(dhcp1.opcode(), DHCP::DISCOVER);
    EXPECT_EQ(dhcp1.htype(), 1);
    ASSERT_EQ(dhcp1.hlen(), (const size_t)EthernetII::address_type::address_size);
    EXPECT_EQ(dhcp1.hops(), 0x1f);
    EXPECT_EQ(dhcp1.xid(), 0x3fab23deU);
    EXPECT_EQ(dhcp1.secs(), 0x9f1a);
    EXPECT_EQ(dhcp1.padding(), 0);
    EXPECT_EQ(dhcp1.ciaddr(), IPv4Address("192.168.0.102"));
    EXPECT_EQ(dhcp1.yiaddr(), IPv4Address("243.22.34.98"));
    EXPECT_EQ(dhcp1.giaddr(), IPv4Address("123.43.55.254"));
    EXPECT_EQ(dhcp1.siaddr(), IPv4Address("167.32.11.154"));
    EXPECT_EQ(dhcp1.server_identifier(), IPv4Address("192.168.4.2"));
    routers = dhcp1.routers();
    EXPECT_EQ(expected_routers, routers);
}

TEST_F(DHCPTest, Serialize) {
    DHCP dhcp1(expected_packet, sizeof(expected_packet));
    PDU::serialization_type buffer = dhcp1.serialize();
    
    ASSERT_EQ(buffer.size(), sizeof(expected_packet));
    EXPECT_TRUE(std::equal(buffer.begin(), buffer.end(), expected_packet));

    DHCP dhcp2(&buffer[0], (uint32_t)buffer.size());
    test_equals(dhcp1, dhcp2);
}

TEST_F(DHCPTest, RemoveOption) {
    DHCP dhcp;
    PDU::serialization_type old_buffer = dhcp.serialize();
    dhcp.domain_name("libtins.github.io");
    dhcp.server_identifier("192.168.0.1");

    EXPECT_TRUE(dhcp.remove_option(DHCP::DOMAIN_NAME));
    EXPECT_TRUE(dhcp.remove_option(DHCP::DHCP_SERVER_IDENTIFIER));

    PDU::serialization_type new_buffer = dhcp.serialize();
    EXPECT_EQ(old_buffer, new_buffer);
}
