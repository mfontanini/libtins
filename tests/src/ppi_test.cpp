#include "dot11/dot11_data.h"
#include "dot11/dot11_beacon.h"

#ifdef TINS_HAVE_DOT11

#include <gtest/gtest.h>
#include <vector>
#include <algorithm>
#include <stdint.h>
#include "ppi.h"
#include "udp.h"

using namespace Tins;

class PPITest : public testing::Test {
public:
    static const uint8_t packet1[], dot11_with_options[];
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

const uint8_t PPITest::dot11_with_options[] = {
    0, 0, 32, 0, 105, 0, 0, 0, 2, 0, 20, 0, 128, 101, 85, 181, 14, 0, 0, 0, 1, 0, 2, 0, 113, 9, 160, 0, 0, 0, 205, 0, 128, 0, 0, 0, 255, 255, 255, 255, 255, 255, 6, 24, 10, 127, 79, 208, 6, 24, 10, 127, 79, 208, 240, 139, 128, 101, 85, 181, 14, 0, 0, 0, 100, 0, 49, 20, 0, 0, 1, 8, 130, 132, 139, 150, 12, 18, 24, 36, 3, 1, 1, 5, 4, 0, 1, 0, 0, 7, 6, 85, 83, 32, 1, 11, 30, 42, 1, 0, 48, 24, 1, 0, 0, 15, 172, 2, 2, 0, 0, 15, 172, 4, 0, 15, 172, 2, 1, 0, 0, 15, 172, 2, 0, 0, 50, 4, 48, 72, 96, 108, 51, 4, 12, 1, 6, 11, 70, 5, 115, 192, 1, 0, 0, 45, 26, 173, 17, 3, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 61, 22, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 221, 26, 0, 80, 242, 1, 1, 0, 0, 80, 242, 2, 2, 0, 0, 80, 242, 4, 0, 80, 242, 2, 1, 0, 0, 80, 242, 2, 221, 24, 0, 80, 242, 2, 1, 1, 138, 0, 3, 164, 0, 0, 39, 164, 0, 0, 66, 67, 94, 0, 98, 50, 47, 0, 221, 9, 0, 3, 127, 1, 1, 0, 0, 255, 127, 221, 13, 0, 24, 10, 7, 0, 0, 0, 0, 1, 0, 20, 63, 198, 54, 63, 126, 205
};

TEST_F(PPITest, ConstructorFromBuffer) {
    PPI pdu(packet1, sizeof(packet1));
    EXPECT_EQ(0, pdu.version());
    EXPECT_EQ(0, pdu.flags());
    EXPECT_EQ(84, pdu.length());
    EXPECT_EQ(105U, pdu.dlt());
    EXPECT_TRUE(pdu.find_pdu<Dot11Data>() != NULL);
    EXPECT_TRUE(pdu.find_pdu<UDP>() != NULL);
}

TEST_F(PPITest, ConstructorFromBufferUsingEncapsulatedDot11WithOptions) {
    PPI pdu(dot11_with_options, sizeof(dot11_with_options));
    EXPECT_EQ(105U, pdu.dlt());
    Dot11Beacon* dot11 = pdu.find_pdu<Dot11Beacon>();
    ASSERT_TRUE(dot11 != NULL);
    EXPECT_TRUE(dot11->search_option(static_cast<Dot11::OptionTypes>(61)) != NULL);
}

#endif // TINS_HAVE_DOT11
