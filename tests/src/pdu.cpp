#include <gtest/gtest.h>
#include <algorithm>
#include <string>
#include <stdint.h>
#include "ip.h"
#include "tcp.h"
#include "rawpdu.h"
#include "pdu.h"

using namespace std;
using namespace Tins;

class PDUTest : public testing::Test {
public:
};

TEST_F(PDUTest, OperatorConcat) {
    std::string raw_payload = "Test";
    IP ip = IP("192.168.0.1") / TCP(22, 52) / RawPDU(raw_payload); 
    EXPECT_EQ(ip.dst_addr(), "192.168.0.1"); 
    ASSERT_TRUE(ip.inner_pdu());
    TCP *tcp = ip.find_pdu<TCP>();
    ASSERT_TRUE(tcp);
    EXPECT_EQ(tcp->dport(), 22);
    EXPECT_EQ(tcp->sport(), 52);
    ASSERT_TRUE(tcp->inner_pdu());
    RawPDU *raw = tcp->find_pdu<RawPDU>();
    ASSERT_TRUE(raw);
    ASSERT_EQ(raw->payload_size(), raw_payload.size());
    EXPECT_TRUE(std::equal(raw_payload.begin(), raw_payload.end(), raw->payload().begin()));
}

