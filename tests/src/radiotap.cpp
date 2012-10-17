#include <gtest/gtest.h>
#include <cstring>
#include <string>
#include <stdint.h>
#include "radiotap.h"
#include "utils.h"

using namespace std;
using namespace Tins;

class RadioTapTest : public testing::Test {
public:
    static const uint8_t expected_packet[];
    
    void test_equals(const RadioTap &radio1, const RadioTap &radio2);
};

const uint8_t RadioTapTest::expected_packet[] = {
    '\x1f', '\x00', ' ', '\x00', 'g', '\x08', '\x04', '\x00', '\x80', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', 'd', '\x00', '\x00', '\x00'
};

TEST_F(RadioTapTest, DefaultConstructor) {
    RadioTap radio;
    EXPECT_TRUE(radio.flags() & RadioTap::FCS);
    EXPECT_EQ(Utils::mhz_to_channel(radio.channel_freq()), 1);
    EXPECT_EQ(radio.channel_type(), 0xa0);
    EXPECT_EQ(radio.tsft(), 0);
    EXPECT_EQ(radio.dbm_signal(), 0xce);
    EXPECT_EQ(radio.antenna(), 0);
    EXPECT_EQ(radio.rx_flags(), 0);
}

//version=0x1f, pad=0x3a, present="TSFT+Antenna"
TEST_F(RadioTapTest, ConstructorFromBuffer) {
    RadioTap radio(expected_packet, sizeof(expected_packet));
    EXPECT_EQ(radio.version(), 0x1f);
    EXPECT_EQ(radio.padding(), 0);
    EXPECT_EQ(radio.antenna(), 2);
    EXPECT_EQ(radio.rate(), 6);
    EXPECT_EQ(radio.rx_flags(), 0);
    EXPECT_EQ(radio.channel_freq(), 5180);
    EXPECT_EQ(radio.channel_type(), 0x140);
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
    EXPECT_EQ(radio.tsft(), 0x7afb9a8d);
}
