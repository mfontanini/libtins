#include "radiotap.h"

#ifdef HAVE_DOT11

#include <gtest/gtest.h>
#include <cstring>
#include <string>
#include <stdint.h>
#include "dot11/dot11_data.h"
#include "dot11/dot11_beacon.h"
#include "utils.h"

using namespace std;
using namespace Tins;

class RadioTapTest : public testing::Test {
public:
    static const uint8_t expected_packet[], expected_packet1[],
                        expected_packet2[];
};

const uint8_t RadioTapTest::expected_packet[] = {
    0, 0, 32, 0, 103, 8, 4, 0, 84, 198, 184, 36, 0, 0, 0, 0, 16, 12, 218, 
    160, 2, 0, 0, 0, 64, 1, 0, 0, 60, 20, 36, 17, 128, 0, 0, 0, 255, 255, 
    255, 255, 255, 255, 6, 3, 127, 7, 160, 22, 6, 3, 127, 7, 160, 22, 176, 
    119, 58, 64, 203, 38, 0, 0, 0, 0, 100, 0, 1, 5, 0, 10, 102, 114, 101, 
    101, 98, 115, 100, 45, 97, 112, 1, 8, 140, 18, 152, 36, 176, 72, 96, 
    108, 3, 1, 36, 5, 4, 0, 1, 0, 0, 7, 42, 85, 83, 32, 36, 1, 17, 40, 
    1, 17, 44, 1, 17, 48, 1, 17, 52, 1, 23, 56, 1, 23, 60, 1, 23, 64, 1, 
    23, 149, 1, 30, 153, 1, 30, 157, 1, 30, 161, 1, 30, 165, 1, 30, 32, 
    1, 0, 221, 24, 0, 80, 242, 2, 1, 1, 0, 0, 3, 164, 0, 0, 39, 164, 0, 
    0, 66, 67, 94, 0, 98, 50, 47, 0, 229, 45, 146, 17
};

const uint8_t RadioTapTest::expected_packet1[] = {
    0, 0, 26, 0, 47, 72, 0, 0, 7, 214, 110, 166, 0, 0, 0, 0, 16, 2, 108, 
    9, 160, 0, 176, 1, 0, 0, 128, 0, 0, 0, 255, 255, 255, 255, 255, 255, 
    124, 79, 181, 147, 114, 92, 124, 79, 181, 147, 114, 92, 128, 104, 71, 
    81, 56, 61, 145, 8, 0, 0, 100, 0, 17, 4, 0, 13, 65, 82, 86, 55, 53, 
    49, 57, 57, 51, 55, 50, 53, 67, 1, 8, 130, 132, 139, 150, 18, 36, 72, 
    108, 3, 1, 1, 50, 4, 12, 24, 48, 96, 7, 6, 78, 76, 32, 1, 13, 20, 51, 
    8, 32, 1, 2, 3, 4, 5, 6, 7, 51, 8, 33, 5, 6, 7, 8, 9, 10, 11, 221, 
    14, 0, 80, 242, 4, 16, 74, 0, 1, 16, 16, 68, 0, 1, 2, 5, 4, 0, 1, 0, 
    0, 42, 1, 4, 45, 26, 108, 0, 23, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 61, 22, 1, 3, 1, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127, 1, 1, 221, 24, 0, 
    80, 242, 1, 1, 0, 0, 80, 242, 2, 1, 0, 0, 80, 242, 2, 1, 0, 0, 80, 
    242, 2, 0, 0, 48, 20, 1, 0, 0, 15, 172, 2, 1, 0, 0, 15, 172, 4, 1, 
    0, 0, 15, 172, 2, 1, 0, 221, 24, 0, 80, 242, 2, 1, 1, 0, 0, 3, 164, 
    0, 0, 39, 164, 0, 0, 66, 67, 94, 0, 98, 50, 47, 0, 11, 5, 0, 0, 39, 
    122, 18, 221, 30, 0, 144, 76, 51, 108, 0, 23, 255, 255, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 221, 26, 0, 144, 
    76, 52, 1, 3, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 145, 139, 60, 178
};

const uint8_t RadioTapTest::expected_packet2[] = {
    0, 0, 34, 0, 47, 72, 0, 0, 166, 1, 78, 68, 1, 0, 0, 0, 2, 18, 143, 9, 
    192, 0, 185, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 136, 66, 223, 0, 0, 33, 
    106, 120, 24, 244, 0, 37, 156, 66, 159, 63, 132, 24, 136, 177, 96, 
    139, 160, 246, 0, 0, 105, 15, 0, 32, 0, 0, 0, 0, 144, 70, 21, 19, 239, 
    128, 176, 53, 109, 131, 215, 214, 175, 122, 48, 125, 96, 224, 165, 
    112, 100, 218, 16, 165, 71, 12, 251, 231, 214, 69, 86, 10, 41, 95, 
    147, 149, 126, 177, 131, 158, 124, 227, 49, 222, 97, 79, 200, 223, 
    132, 241, 42, 135, 151, 94, 223, 190, 109, 180, 255, 115, 238, 211
};

TEST_F(RadioTapTest, DefaultConstructor) {
    RadioTap radio;
    EXPECT_TRUE(radio.flags() & RadioTap::FCS);
    EXPECT_EQ(Utils::mhz_to_channel(radio.channel_freq()), 1);
    EXPECT_EQ(radio.channel_type(), 0xa0U);
    EXPECT_EQ(radio.tsft(), 0U);
    EXPECT_EQ(radio.dbm_signal(), 0xce);
    EXPECT_EQ(radio.antenna(), 0);
    EXPECT_EQ(radio.rx_flags(), 0);
}

TEST_F(RadioTapTest, ConstructorFromBuffer) {
    RadioTap radio(expected_packet, sizeof(expected_packet));
    EXPECT_EQ(radio.version(), 0);
    EXPECT_EQ(radio.length(), 32);
    EXPECT_EQ(radio.rate(), 0xc);
    EXPECT_EQ(radio.flags(), 0x10);
    
    EXPECT_TRUE(radio.present() & RadioTap::TSTF);
    EXPECT_TRUE(radio.present() & RadioTap::RATE);
    EXPECT_TRUE(radio.present() & RadioTap::DBM_SIGNAL);
    EXPECT_TRUE(radio.present() & RadioTap::ANTENNA);
    EXPECT_TRUE(radio.present() & RadioTap::CHANNEL_PLUS);
    
    EXPECT_TRUE(radio.flags() & RadioTap::FCS);
    EXPECT_EQ(radio.channel_type(), 0x140);
    EXPECT_EQ(radio.channel_freq(), 5180);
    EXPECT_EQ(radio.tsft(), 616089172U);
    EXPECT_EQ(radio.dbm_signal(), 0xda);
    EXPECT_EQ(radio.dbm_noise(), 0xa0);
    EXPECT_EQ(radio.antenna(), 2);
}

TEST_F(RadioTapTest, ConstructorFromBuffer1) {
    RadioTap radio(expected_packet1, sizeof(expected_packet1));
    EXPECT_EQ(radio.version(), 0);
    EXPECT_EQ(radio.length(), 26);
    EXPECT_EQ(radio.rate(), 2);
    EXPECT_EQ(radio.flags(), 0x10);
    EXPECT_TRUE(radio.flags() & RadioTap::FCS);
    EXPECT_EQ(radio.antenna(), 1);
    EXPECT_TRUE(radio.find_pdu<Dot11Beacon>());
}

TEST_F(RadioTapTest, ConstructorFromBuffer2) {
    RadioTap radio(expected_packet2, sizeof(expected_packet2));
    
    EXPECT_TRUE(radio.present() & RadioTap::RATE);
    EXPECT_TRUE(radio.present() & RadioTap::CHANNEL);
    EXPECT_TRUE(radio.present() & RadioTap::DBM_SIGNAL);
    EXPECT_TRUE(radio.present() & RadioTap::ANTENNA);
    EXPECT_TRUE(radio.present() & RadioTap::RX_FLAGS);
    
    EXPECT_EQ(radio.version(), 0);
    EXPECT_EQ(radio.length(), 34);
    EXPECT_EQ(radio.rate(), 0x12);
    EXPECT_EQ(radio.flags(), 0x02);
    EXPECT_EQ(radio.dbm_signal(), 0xb9);
    EXPECT_EQ(radio.channel_type(), 192);
    EXPECT_EQ(radio.channel_freq(), 2447);
    EXPECT_EQ(radio.antenna(), 0);
    EXPECT_TRUE(radio.find_pdu<Dot11QoSData>());
}

TEST_F(RadioTapTest, Serialize) {
    RadioTap radio(expected_packet, sizeof(expected_packet));
    RadioTap::serialization_type buffer = radio.serialize();
    
    ASSERT_EQ(buffer.size(), sizeof(expected_packet));
    
    EXPECT_TRUE(std::equal(buffer.begin(), buffer.end(), expected_packet));
}

TEST_F(RadioTapTest, Channel) {
    RadioTap radio;
    radio.channel(0xfa23, 0xfb6a);
    EXPECT_EQ(radio.channel_freq(), 0xfa23);
    EXPECT_EQ(radio.channel_type(), 0xfb6a);
}

TEST_F(RadioTapTest, Antenna) {
    RadioTap radio;
    radio.antenna(0x7a);
    EXPECT_EQ(radio.antenna(), 0x7a);
}

TEST_F(RadioTapTest, Padding) {
    RadioTap radio;
    radio.padding(0x7a);
    EXPECT_EQ(radio.padding(), 0x7a);
}

TEST_F(RadioTapTest, Version) {
    RadioTap radio;
    radio.version(0x7a);
    EXPECT_EQ(radio.version(), 0x7a);
}

TEST_F(RadioTapTest, Length) {
    RadioTap radio;
    radio.length(0x7a);
    EXPECT_EQ(radio.length(), 0x7a);
}

TEST_F(RadioTapTest, DBMSignal) {
    RadioTap radio;
    radio.dbm_signal(0x7a);
    EXPECT_EQ(radio.dbm_signal(), 0x7a);
}

TEST_F(RadioTapTest, DBMNoise) {
    RadioTap radio;
    radio.dbm_noise(0x7a);
    EXPECT_EQ(radio.dbm_noise(), 0x7a);
}

TEST_F(RadioTapTest, RXFlags) {
    RadioTap radio;
    radio.rx_flags(0x7afb);
    EXPECT_EQ(radio.rx_flags(), 0x7afb);
}

TEST_F(RadioTapTest, Rate) {
    RadioTap radio;
    radio.rate(0x7a);
    EXPECT_EQ(radio.rate(), 0x7a);
}

TEST_F(RadioTapTest, TSFT) {
    RadioTap radio;
    radio.tsft(0x7afb9a8d);
    EXPECT_EQ(radio.tsft(), 0x7afb9a8dU);
}

#endif // HAVE_DOT11
