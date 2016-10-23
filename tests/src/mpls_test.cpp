#include <gtest/gtest.h>
#include <cstring>
#include <string>
#include <algorithm>
#include <stdint.h>
#include "mpls.h"
#include "ip.h"
#include "udp.h"
#include "rawpdu.h"
#include "ethernetII.h"

using namespace std;
using namespace Tins;

class MPLSTest : public testing::Test {
public:
    static const uint8_t eth_and_mpls[];
    static const uint8_t mpls_layer[];
};

const uint8_t MPLSTest::eth_and_mpls[] = {
    0, 1, 1, 0, 0, 2, 0, 1, 1, 0, 0, 1, 136, 71, 0, 62, 144, 128, 0, 62, 
    160, 128, 0, 62, 177, 128, 69, 0, 0, 39, 147, 163, 0, 0, 128, 17, 
    169, 32, 127, 0, 0, 1, 127, 0, 0, 1, 0, 7, 0, 7, 0, 19, 35, 34, 72, 
    101, 108, 108, 111, 32, 77, 80, 76, 83, 33
};

const uint8_t MPLSTest::mpls_layer[] = {
    24, 150, 1, 1
};

TEST_F(MPLSTest, ConstructWholePacket) {
    // This has 3 MPLS labels
    EthernetII eth(eth_and_mpls, sizeof(eth_and_mpls));
    const MPLS* mpls1 = eth.find_pdu<MPLS>();
    ASSERT_TRUE(mpls1 != 0);
    ASSERT_TRUE(mpls1->inner_pdu() != 0);

    const MPLS* mpls2 = mpls1->inner_pdu()->find_pdu<MPLS>();
    ASSERT_TRUE(mpls2 != 0);
    ASSERT_TRUE(mpls2->inner_pdu() != 0);

    const MPLS* mpls3 = mpls2->inner_pdu()->find_pdu<MPLS>();
    ASSERT_TRUE(mpls3 != 0);
    ASSERT_TRUE(mpls3->inner_pdu() != 0);

    const IP* ip = mpls3->find_pdu<IP>();
    ASSERT_TRUE(ip != 0);

    const RawPDU* raw = ip->find_pdu<RawPDU>();
    ASSERT_TRUE(raw != 0);

    string payload = "Hello MPLS!";
    EXPECT_EQ(RawPDU::payload_type(payload.begin(), payload.end()), raw->payload());

    MPLS::serialization_type buffer = eth.serialize();
    EXPECT_EQ(
        MPLS::serialization_type(eth_and_mpls, eth_and_mpls + sizeof(eth_and_mpls)),
        buffer
    );
}

TEST_F(MPLSTest, ConstructorFromBuffer) {
    MPLS mpls(mpls_layer, sizeof(mpls_layer));
    EXPECT_EQ(100704U, mpls.label());
    EXPECT_EQ(1, mpls.bottom_of_stack());
    EXPECT_EQ(1, mpls.ttl());
}

TEST_F(MPLSTest, Serialize) {
    MPLS mpls(mpls_layer, sizeof(mpls_layer));
    MPLS::serialization_type buffer = mpls.serialize();
    EXPECT_EQ(
        MPLS::serialization_type(mpls_layer, mpls_layer + sizeof(mpls_layer)),
        buffer
    );
}

TEST_F(MPLSTest, SerializeAfterEthernet) {
    EthernetII eth = EthernetII() / MPLS() / IP() / UDP() / RawPDU("hehehe");
    eth.serialize();
    // Bottom of stack should be 1
    EXPECT_EQ(1, eth.rfind_pdu<MPLS>().bottom_of_stack());
}

TEST_F(MPLSTest, SerializeAfterEthernetUsingTwoMPLSLayers) {
    EthernetII eth = EthernetII() / MPLS() / MPLS() / IP() / UDP() / RawPDU("hehehe");
    eth.serialize();

    const MPLS& mpls1 = eth.rfind_pdu<MPLS>();
    const MPLS& mpls2 = mpls1.inner_pdu()->rfind_pdu<MPLS>();
    // Bottom of stack should be 0 for the first MPLS layer
    EXPECT_EQ(0, mpls1.bottom_of_stack());
    // 1 for the second one
    EXPECT_EQ(1, mpls2.bottom_of_stack());
}

TEST_F(MPLSTest, SetAllFields) {
    MPLS mpls;
    mpls.ttl(0xde);
    mpls.bottom_of_stack(1);
    mpls.label(0xdead8);
    EXPECT_EQ(0xdead8U, mpls.label());
    EXPECT_EQ(1, mpls.bottom_of_stack());
    EXPECT_EQ(0xde, mpls.ttl());
}

TEST_F(MPLSTest, Label) {
    MPLS mpls;
    mpls.label(0xdead8);
    EXPECT_EQ(0xdead8U, mpls.label());
}

TEST_F(MPLSTest, BottomOfStack) {
    MPLS mpls;
    mpls.bottom_of_stack(1);
    EXPECT_EQ(1, mpls.bottom_of_stack());
}

TEST_F(MPLSTest, TTL) {
    MPLS mpls;
    mpls.ttl(0xde);
    EXPECT_EQ(0xde, mpls.ttl());
}
