#include "dot11/dot11_data.h"

#ifdef HAVE_DOT11

#include <gtest/gtest.h>
#include <vector>
#include <algorithm>
#include <stdint.h>
#include "ppi.h"
#include "udp.h"

using namespace Tins;

class PPITest : public testing::Test {
public:
    static const uint8_t packet1[];
};

const uint8_t PPITest::packet1[] = {
    0, 0, 84, 0, 105, 0, 0, 0, 2, 0, 20, 0, 99, 126, 205, 243, 0, 0, 0, 
    0, 1, 0, 88, 2, 118, 9, 192, 0, 0, 0, 200, 160, 4, 0, 48, 0, 6, 0, 
    0, 0, 2, 0, 0, 0, 0, 15, 2, 40, 34, 34, 30, 255, 36, 39, 33, 255, 
    138, 9, 192, 0, 194, 160, 194, 160, 190, 160, 128, 128, 22, 17, 19, 
    29, 21, 17, 23, 22, 25, 18, 26, 22, 0, 0, 0, 0, 136, 1, 44, 0, 0, 
    20, 165, 205, 116, 123, 0, 20, 165, 203, 110, 26, 0, 1, 2, 39, 249, 
    178, 160, 237, 0, 0, 170, 170, 3, 0, 0, 0, 8, 0, 69, 0, 0, 59, 141, 
    6, 0, 0, 128, 17, 41, 214, 192, 168, 1, 132, 192, 168, 1, 1, 4, 7, 
    0, 53, 0, 39, 171, 21, 150, 193, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, 
    119, 119, 119, 6, 112, 111, 108, 105, 116, 111, 2, 105, 116, 0, 0, 
    1, 0, 1, 120, 128, 89, 55
};

TEST_F(PPITest, ConstructorFromBuffer) {
    PPI pdu(packet1, sizeof(packet1));
    EXPECT_EQ(0, pdu.version());
    EXPECT_EQ(0, pdu.flags());
    EXPECT_EQ(84, pdu.length());
    EXPECT_EQ(105U, pdu.dlt());
    EXPECT_TRUE(pdu.find_pdu<Dot11Data>());
    EXPECT_TRUE(pdu.find_pdu<UDP>());
}

#endif // HAVE_DOT11
