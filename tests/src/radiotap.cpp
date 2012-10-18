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
    '\x00', '\x00', ' ', '\x00', 'g', '\x08', '\x04', '\x00', 'T', '\xc6', 
    '\xb8', '$', '\x00', '\x00', '\x00', '\x00', '"', '\x0c', '\xda', 
    '\xa0', '\x02', '\x00', '\x00', '\x00', '@', '\x01', '\x00', '\x00', 
    '<', '\x14', '$', '\x11', '\x80', '\x00', '\x00', '\x00', '\xff', 
    '\xff', '\xff', '\xff', '\xff', '\xff', '\x06', '\x03', '\x7f', 
    '\x07', '\xa0', '\x16', '\x06', '\x03', '\x7f', '\x07', '\xa0', 
    '\x16', '\xb0', 'w', ':', '@', '\xcb', '&', '\x00', '\x00', '\x00', 
    '\x00', 'd', '\x00', '\x01', '\x05', '\x00', '\n', 'f', 'r', 'e', 
    'e', 'b', 's', 'd', '-', 'a', 'p', '\x01', '\x08', '\x8c', '\x12', 
    '\x98', '$', '\xb0', 'H', '`', 'l', '\x03', '\x01', '$', '\x05', 
    '\x04', '\x00', '\x01', '\x00', '\x00', '\x07', '*', 'U', 'S', ' ', 
    '$', '\x01', '\x11', '(', '\x01', '\x11', ',', '\x01', '\x11', '0', 
    '\x01', '\x11', '4', '\x01', '\x17', '8', '\x01', '\x17', '<', '\x01', 
    '\x17', '@', '\x01', '\x17', '\x95', '\x01', '\x1e', '\x99', '\x01', 
    '\x1e', '\x9d', '\x01', '\x1e', '\xa1', '\x01', '\x1e', '\xa5', '\x01', 
    '\x1e', ' ', '\x01', '\x00', '\xdd', '\x18', '\x00', 'P', '\xf2', 
    '\x02', '\x01', '\x01', '\x00', '\x00', '\x03', '\xa4', '\x00', '\x00', 
    '\'', '\xa4', '\x00', '\x00', 'B', 'C', '^', '\x00', 'b', '2', '/', '\x00'
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

TEST_F(RadioTapTest, ConstructorFromBuffer) {
    RadioTap radio(expected_packet, sizeof(expected_packet));
    EXPECT_EQ(radio.version(), 0);
    EXPECT_EQ(radio.channel_type(), 0x140);
    EXPECT_EQ(radio.tsft(), 616089172);
    EXPECT_EQ(radio.dbm_signal(), 0xda);
    EXPECT_EQ(radio.dbm_noise(), 0xa0);
    EXPECT_EQ(radio.antenna(), 2);
    EXPECT_EQ(radio.rx_flags(), 0);
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
    EXPECT_EQ(radio.tsft(), 0x7afb9a8d);
}
