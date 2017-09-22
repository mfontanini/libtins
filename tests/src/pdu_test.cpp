#include <gtest/gtest.h>
#include <algorithm>
#include <string>
#include <stdint.h>
#include <tins/ip.h>
#include <tins/tcp.h>
#include <tins/udp.h>
#include <tins/rawpdu.h>
#include <tins/pdu.h>
#include <tins/packet.h>

using namespace std;
using namespace Tins;

class PDUTest : public testing::Test {
public:
};

TEST_F(PDUTest, FindPDU) {
    IP ip = IP("192.168.0.1") / TCP(22, 52) / RawPDU("Test");
    EXPECT_TRUE(ip.find_pdu<TCP>() != NULL);
    EXPECT_TRUE(ip.find_pdu<RawPDU>() != NULL);
    EXPECT_FALSE(ip.find_pdu<UDP>() != NULL);
    TCP& t1 = ip.rfind_pdu<TCP>();
    const TCP& t2 = ip.rfind_pdu<TCP>();
    (void)t1;
    (void)t2;
    EXPECT_THROW(ip.rfind_pdu<UDP>(), pdu_not_found);
}

TEST_F(PDUTest, PDURelationship) {
    IP packet = IP("192.168.0.1") / TCP(22, 52) / RawPDU("Test");
    IP* ip = packet.find_pdu<IP>();
    TCP* tcp = packet.find_pdu<TCP>();
    RawPDU* raw = packet.find_pdu<RawPDU>();

    ASSERT_TRUE(ip != 0);
    ASSERT_TRUE(tcp != 0);
    ASSERT_TRUE(raw != 0);

    EXPECT_EQ(0, ip->parent_pdu());
    EXPECT_EQ(ip, tcp->parent_pdu());
    EXPECT_EQ(tcp, raw->parent_pdu());
}

TEST_F(PDUTest, OperatorConcat) {
    std::string raw_payload = "Test";
    IP ip = IP("192.168.0.1") / TCP(22, 52) / RawPDU(raw_payload); 
    EXPECT_EQ(ip.dst_addr(), "192.168.0.1"); 
    ASSERT_TRUE(ip.inner_pdu() != NULL);
    TCP* tcp = ip.find_pdu<TCP>();
    ASSERT_TRUE(tcp != NULL);
    EXPECT_EQ(tcp->dport(), 22);
    EXPECT_EQ(tcp->sport(), 52);
    ASSERT_TRUE(tcp->inner_pdu() != NULL);
    RawPDU* raw = tcp->find_pdu<RawPDU>();
    ASSERT_TRUE(raw != NULL);
    ASSERT_EQ(raw->payload_size(), raw_payload.size());
    EXPECT_TRUE(std::equal(raw_payload.begin(), raw_payload.end(), raw->payload().begin()));
}

TEST_F(PDUTest, OperatorConcatOnPointers) {
    std::string raw_payload = "Test";
    IP ip = IP("192.168.0.1") / TCP(22, 52);
    TCP* tcp = ip.find_pdu<TCP>();
    ASSERT_TRUE(tcp != NULL);
    tcp /= RawPDU(raw_payload);
    RawPDU* raw = ip.find_pdu<RawPDU>();
    ASSERT_TRUE(raw != NULL);
    ASSERT_EQ(raw->payload_size(), raw_payload.size());
    EXPECT_TRUE(std::equal(raw->payload().begin(), raw->payload().end(), raw_payload.begin()));
}

TEST_F(PDUTest, OperatorConcatOnPacket) {
    std::string raw_payload = "Test";
    Packet packet = IP("192.168.0.1") / TCP(22, 52);
    TCP* tcp = packet.pdu()->find_pdu<TCP>();
    ASSERT_TRUE(tcp != NULL);
    tcp /= RawPDU(raw_payload);
    RawPDU* raw = packet.pdu()->find_pdu<RawPDU>();
    ASSERT_TRUE(raw != NULL);
    ASSERT_EQ(raw->payload_size(), raw_payload.size());
    EXPECT_TRUE(std::equal(raw->payload().begin(), raw->payload().end(), raw_payload.begin()));
}

TEST_F(PDUTest, TinsCast) {
    PDU* null_pdu = 0;
    TCP tcp;
    PDU* pdu = &tcp;
    EXPECT_EQ(tins_cast<TCP*>(pdu), &tcp);
    EXPECT_EQ(tins_cast<const TCP*>(pdu), &tcp);
    EXPECT_EQ(tins_cast<TCP*>(null_pdu), null_pdu);
    EXPECT_EQ(tins_cast<UDP*>(pdu), null_pdu);
    EXPECT_THROW(tins_cast<UDP>(*pdu), bad_tins_cast);
}

