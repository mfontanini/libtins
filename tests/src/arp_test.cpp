#include <gtest/gtest.h>
#include <cstring>
#include <string>
#include <iostream>
#include <stdint.h>
#include "arp.h"
#include "utils.h"
#include "ip_address.h"


using namespace std;
using namespace Tins;

typedef ARP::hwaddress_type address_type;

class ARPTest : public testing::Test {
public:
    static const address_type empty_addr;
    static const address_type hw_addr1;
    static const address_type hw_addr2;
    static const string ip_addr1;
    static const uint8_t expected_packet[];
    static const IPv4Address addr1, addr2;

    void test_equals(const ARP& arp1, const ARP& arp2);
};

const address_type ARPTest::empty_addr;
const address_type ARPTest::hw_addr1("13:da:de:f1:01:85");
const address_type ARPTest::hw_addr2("7a:1f:f4:39:ab:0d");
const uint8_t ARPTest::expected_packet[] = {
    0, 1, 8, 0, 6, 4, 0, 2, 3, 222, 245, 18, 9, 250, 192, 168, 45, 231, 
    245, 18, 218, 103, 189, 13, 32, 155, 81, 254
};
const IPv4Address ARPTest::addr1(0x1234), ARPTest::addr2(0xa3f1);

void ARPTest::test_equals(const ARP& arp1, const ARP& arp2) {
    EXPECT_EQ(arp1.opcode(), arp2.opcode());
    ASSERT_EQ(arp1.hw_addr_length(), arp2.hw_addr_length());
    EXPECT_EQ(arp1.hw_addr_format(), arp2.hw_addr_format());
    ASSERT_EQ(arp1.prot_addr_length(), arp2.prot_addr_length());
    EXPECT_EQ(arp1.prot_addr_format(), arp2.prot_addr_format());
    EXPECT_EQ(arp1.sender_ip_addr(), arp2.sender_ip_addr());
    EXPECT_EQ(arp1.target_ip_addr(), arp2.target_ip_addr());
    EXPECT_EQ(arp1.sender_hw_addr(), arp2.sender_hw_addr());
    EXPECT_EQ(arp1.target_hw_addr(), arp2.target_hw_addr());
    EXPECT_EQ(arp1.inner_pdu() != NULL, arp2.inner_pdu() != NULL);
}

TEST_F(ARPTest, DefaultContructor) {
    ARP arp;
    EXPECT_EQ(arp.target_ip_addr(), IPv4Address());
    EXPECT_EQ(arp.sender_ip_addr(), IPv4Address());
    EXPECT_EQ(arp.target_hw_addr(), empty_addr);
    EXPECT_EQ(arp.target_hw_addr(), empty_addr);
    EXPECT_EQ(arp.pdu_type(), PDU::ARP);
}

TEST_F(ARPTest, CopyContructor) {
    ARP arp1(addr1, addr2, hw_addr1, hw_addr2);
    ARP arp2(arp1);
    test_equals(arp1, arp2);
}

TEST_F(ARPTest, CopyAssignmentOperator) {
    ARP arp1(addr1, addr2, hw_addr1, hw_addr2);
    ARP arp2 = arp1;
    test_equals(arp1, arp2);
}

TEST_F(ARPTest, NestedCopy) {
    ARP* nested_arp = new ARP(addr1, addr2, hw_addr1, hw_addr2);
    ARP arp1(addr1, addr2, hw_addr1, hw_addr2);
    arp1.inner_pdu(nested_arp);
    ARP arp2(arp1);
    test_equals(arp1, arp2);
}

TEST_F(ARPTest, CompleteContructor) {
    ARP arp(addr1, addr2, hw_addr1, hw_addr2);
    EXPECT_EQ(arp.target_hw_addr(), hw_addr1);
    EXPECT_EQ(arp.sender_hw_addr(), hw_addr2);
    EXPECT_EQ(arp.target_ip_addr(), addr1);
    EXPECT_EQ(arp.sender_ip_addr(), addr2);
}

TEST_F(ARPTest, SenderIPAddrInt) {
    ARP arp;
    arp.sender_ip_addr(addr1);
    EXPECT_EQ(arp.sender_ip_addr(), addr1);
}

TEST_F(ARPTest, TargetIPAddrInt) {
    ARP arp;
    arp.target_ip_addr(addr1);
    EXPECT_EQ(arp.target_ip_addr(), addr1);
}

TEST_F(ARPTest, TargetHWAddr) {
    ARP arp;
    arp.target_hw_addr(hw_addr1);
    EXPECT_EQ(arp.target_hw_addr(), hw_addr1);
}

TEST_F(ARPTest, SenderHWAddr) {
    ARP arp;
    arp.sender_hw_addr(hw_addr1);
    EXPECT_EQ(arp.sender_hw_addr(), hw_addr1);
}

TEST_F(ARPTest, ProtAddrFormat) {
    ARP arp;
    arp.prot_addr_format(0x45fa);
    EXPECT_EQ(arp.prot_addr_format(), 0x45fa);
}

TEST_F(ARPTest, ProtAddrLength) {
    ARP arp;
    arp.prot_addr_length(0x4f);
    EXPECT_EQ(arp.prot_addr_length(), 0x4f);
}

TEST_F(ARPTest, HWAddrFormat) {
    ARP arp;
    arp.hw_addr_format(0x45fa);
    EXPECT_EQ(arp.hw_addr_format(), 0x45fa);
}

TEST_F(ARPTest, HWAddrLength) {
    ARP arp;
    arp.hw_addr_length(0xd1);
    EXPECT_EQ(arp.hw_addr_length(), 0xd1);
}

TEST_F(ARPTest, Opcode) {
    ARP arp;
    arp.opcode(ARP::REQUEST);
    EXPECT_EQ(arp.opcode(), ARP::REQUEST);
}

TEST_F(ARPTest, Serialize) {
    ARP arp1("192.168.0.1", "192.168.0.100", hw_addr1, hw_addr2);
    
    PDU::serialization_type buffer = arp1.serialize();
    
    ARP arp2(arp1);
    PDU::serialization_type buffer2 = arp2.serialize();
    EXPECT_EQ(buffer, buffer2);
}

TEST_F(ARPTest, ConstructorFromBuffer) {
    ARP arp1(expected_packet, sizeof(expected_packet));
    PDU::serialization_type buffer = arp1.serialize();
    
    ARP arp2(&buffer[0], (uint32_t)buffer.size());
    EXPECT_EQ(arp1.opcode(), arp2.opcode());
    ASSERT_EQ(arp1.hw_addr_length(), arp2.hw_addr_length());
    EXPECT_EQ(arp1.hw_addr_format(), arp2.hw_addr_format());
    ASSERT_EQ(arp1.prot_addr_length(), arp2.prot_addr_length());
    EXPECT_EQ(arp1.prot_addr_format(), arp2.prot_addr_format());
    EXPECT_EQ(arp1.sender_ip_addr(), arp2.sender_ip_addr());
    EXPECT_EQ(arp1.target_ip_addr(), arp2.target_ip_addr());
    EXPECT_EQ(arp1.sender_hw_addr(), arp2.sender_hw_addr());
    EXPECT_EQ(arp1.target_hw_addr(), arp2.target_hw_addr());
}
