#include <gtest/gtest.h>
#include <cstring>
#include <string>
#include <iostream>
#include <stdint.h>
#include "pktap.h"

using namespace std;
using namespace Tins;


class PKTAPTest : public testing::Test {
public:
    static const uint8_t packet1[];
};

const uint8_t PKTAPTest::packet1[] = {
    108, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 101, 110, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 14, 0, 0, 0, 0, 0, 0, 0, 178, 7, 0, 0, 111, 99, 115, 112, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 128, 57, 251, 101, 187, 44, 240, 238, 33, 128, 46, 8, 0, 69, 0, 0, 40, 188, 8, 64, 0, 64, 6, 70, 77, 10, 0, 0, 222, 17, 151, 28, 6, 196, 70, 0, 80, 63, 40, 147, 97, 101, 156, 12, 242, 80, 17, 64, 0, 45, 170, 0, 0
};


TEST_F(PKTAPTest, ConstructorFromBuffer) {
    PKTAP pkt(packet1, sizeof(packet1));
    PDU* inner = pkt.inner_pdu();
    ASSERT_TRUE(inner != NULL);
    EXPECT_EQ(PDU::ETHERNET_II, inner->pdu_type());
}
