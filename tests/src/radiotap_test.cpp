#include "radiotap.h"

#ifdef TINS_HAVE_DOT11

#include <gtest/gtest.h>
#include <cstring>
#include <string>
#include <stdint.h>
#include "dot11/dot11_data.h"
#include "dot11/dot11_beacon.h"
#include "arp.h"
#include "snap.h"
#include "eapol.h"
#include "utils.h"

using namespace std;
using namespace Tins;

class RadioTapTest : public testing::Test {
public:
    static const uint8_t expected_packet[], expected_packet1[],
                        expected_packet2[], expected_packet3[],
                        expected_packet4[], expected_packet5[];
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

const uint8_t RadioTapTest::expected_packet3[] = {
    0, 0, 36, 0, 47, 64, 0, 160, 32, 8, 0, 0, 0, 0, 0, 0, 75, 136, 126,
     238, 50, 0, 0, 0, 18, 22, 133, 9, 192, 0, 181, 0, 0, 0, 181, 0, 8, 
     2, 0, 0, 255, 255, 255, 255, 255, 255, 116, 37, 138, 78, 207, 112, 
     0, 102, 75, 134, 135, 47, 32, 84, 170, 170, 3, 0, 0, 0, 8, 6, 0, 1, 
     8, 0, 6, 4, 0, 1, 0, 102, 75, 134, 135, 47, 172, 31, 30, 115, 0, 0, 
     0, 0, 0, 0, 172, 31, 31, 105, 106, 113, 120, 145
};

const uint8_t RadioTapTest::expected_packet4[] = {
    0, 0, 39, 0, 43, 64, 8, 160, 32, 8, 0, 0, 0, 0, 0, 0, 222, 24, 
    122, 92, 227, 1, 0, 0, 16, 0, 108, 9, 128, 4, 186, 0, 0, 0, 39, 0
    , 1, 186, 0, 136, 66, 48, 0, 208, 231, 130, 247, 98, 61, 76, 158,
    255, 127, 13, 247, 226, 145, 245, 204, 218, 252, 112, 242, 0, 0,
    43, 203, 0, 32, 11, 0, 0, 0, 14, 127, 184, 209, 44, 105, 69, 251
    , 60, 61, 163, 101, 84, 74, 221, 98, 99, 67, 102, 27, 57, 87, 39,
    188, 200, 78, 21, 9, 29, 221, 96, 41, 207, 67, 74, 203, 34, 213,
    177, 33, 98, 185, 68, 218, 127, 231, 39, 108, 110, 216, 154, 228
    , 13, 12, 143, 59, 104, 185, 40, 177, 120, 162, 80, 99, 72, 39, 
    66, 103, 244, 85, 89, 181, 34, 131, 26, 50, 229, 201, 62, 78, 95,
    114, 173, 139, 218, 18, 111, 31, 185, 194, 244, 186, 249, 168, 
    178, 214, 63, 159, 238, 50, 5, 176, 178, 221, 87, 124, 22, 183, 
    108, 231, 228, 98, 211, 62, 254, 223, 161, 137, 30, 130, 210, 158
    , 241, 237, 174, 208, 67, 233, 130, 56, 95, 40, 183, 161, 229, 
    227, 121, 112, 191, 106, 225, 164, 78, 90, 211, 179, 193, 211, 72
    , 225, 109, 112, 58, 61, 64, 128, 13, 195, 221, 100, 214, 214, 
    165, 154, 73, 64, 19, 212, 8, 108, 246, 72, 97, 189, 4, 88, 245, 
    97, 3, 48, 37, 178, 216, 169, 59, 177, 36, 159, 255, 104, 106, 
    130, 196, 199, 88, 59, 55, 151, 247, 159, 54, 227, 214, 114, 128,
    255, 17, 6, 34, 150, 48, 234, 237, 98, 226, 146, 207, 192, 6, 49
    , 247, 106, 253, 252, 196, 250, 34, 191, 51, 124, 83, 188, 30, 
    254, 217, 186, 70, 182, 117, 74, 55, 129, 253, 88, 43, 161, 182, 
    239, 24, 79, 64, 228, 168, 202, 235, 148, 134, 47, 89, 86, 123, 
    86, 64, 211, 53, 199, 187, 40, 212, 19, 226, 253, 55, 186, 58, 11
    , 231, 114, 69, 67, 63, 139, 97, 204, 155, 122, 219, 71, 75, 82, 
    155, 225, 241, 11, 111, 162, 148, 2, 11, 60, 14, 62, 176, 62, 80,
    190, 59, 35, 190, 221, 11, 246, 166, 166, 12, 38, 109, 208, 161,
    178, 31, 72, 179, 22, 161, 169, 132, 45, 21, 34, 0, 114, 214, 91
    , 62, 51, 70, 95, 108, 72, 156, 129, 32, 26, 162, 97, 139, 156, 
    156, 85, 142, 163, 222, 11, 63, 203, 129, 159, 230, 225, 20, 87, 
    185, 59, 50, 247, 217, 31, 181, 80, 164, 0, 82, 57, 7, 195, 42, 
    219, 231, 163, 22, 250, 255, 143, 106, 17, 198, 232, 119, 172, 
    184, 189, 6, 246, 92, 220, 99, 104, 255, 145, 78, 5, 17, 71, 135,
    116, 126, 194, 119, 50, 121, 177, 38, 161, 132, 229, 235, 88, 
    106, 134, 50, 232, 218, 146, 9, 15, 150, 167, 199, 84, 149, 155, 
    252, 16, 237, 4, 250, 155, 30, 130, 244, 68, 188, 122, 8, 6, 167,
    61, 145, 187, 18, 24, 106, 241, 236, 89, 27, 139, 132, 220, 152,
    186, 1, 248, 40, 64, 162, 157, 246, 130, 228, 141, 223, 186, 51,
    166, 53, 53, 201, 231, 70, 198, 70, 254, 124, 125, 44, 89, 181, 
    187, 19, 244, 67, 195, 179, 137, 21, 214, 227, 191, 216, 172, 165
    , 213, 155, 241, 212, 249, 167, 135, 216, 33, 197, 155, 0, 70, 37
    , 124, 217, 168, 113, 75, 189, 74, 253, 199, 157, 236, 187, 132, 
    249, 98, 129, 74, 57, 10, 202, 200, 103, 78, 139, 186, 24, 109, 
    161, 201, 68, 156, 188, 139, 129, 165, 137, 73, 53, 106, 204, 22,
    228, 115, 101, 155, 123, 105, 111, 250, 181, 204, 48, 126, 216, 
    159, 2, 9, 194, 225, 193, 163, 193, 87, 244, 200, 220, 226, 12, 
    25, 117, 201, 52, 133, 229, 151, 27, 37, 60, 67, 112, 25, 184, 5,
    255, 189, 87, 141, 81, 89, 253, 195, 126, 29, 12, 157, 194, 239,
    1, 71, 65, 84, 37, 205, 114, 5, 209, 249, 74, 201, 169, 191, 150
    , 248, 250, 212, 124, 199, 51, 114, 56, 28, 184, 2, 110, 254, 84,
    30, 55, 254, 72, 138, 55, 139, 103, 9, 49, 74, 20, 165, 72, 252,
    231, 140, 183, 170, 223, 80, 140, 238, 108, 79, 53, 217, 64, 48,
    191, 67, 177, 171, 25, 48, 253, 232, 87, 247, 60, 160, 171, 111,
    149, 169, 71, 30, 120, 57, 255, 25, 249, 82, 108, 232, 161, 7, 
    230, 163, 177, 15, 10, 122, 135, 97, 26, 197, 229, 223, 245, 249,
    129, 45, 52, 139, 60, 205, 43, 106, 234, 139, 200, 217, 177, 54,
    183, 62, 154, 151, 63, 163, 227, 191, 137, 216, 25, 137, 195, 
    156, 161, 90, 101, 244, 79, 13, 86, 129, 233, 36, 20, 171, 29, 
    235, 21, 228, 26, 119, 84, 110, 170, 164, 159, 35, 18, 124, 169, 
    2, 157, 107, 18, 86, 91, 58, 97, 159, 60, 27, 128, 93, 237, 189, 
    148, 26, 122, 8, 59, 21, 188, 200, 102, 26, 223, 15, 81, 143, 149
    , 141, 41, 163, 244, 29, 84, 129, 165, 11, 35, 91, 127, 87, 153, 
    60, 9, 209, 92, 197, 156, 168, 72, 148, 137, 124, 228, 21, 245, 
    248, 176, 99, 199, 27, 66, 166, 67, 194, 39, 19, 36, 211, 11, 23,
    36, 139, 53, 171, 119, 39, 194, 241, 36, 6, 68, 214, 247, 58, 85
    , 167, 86, 241, 38, 95, 204, 68, 120, 115, 218, 241, 206, 231, 15
    , 146, 64, 132, 69, 159, 246, 209, 5, 37, 93, 158, 26, 6, 130, 
    158, 249, 56, 48, 1, 243, 80, 4, 111, 144, 6, 116, 93, 196, 164, 
    249, 115, 3, 162, 26, 131, 203, 83, 156, 18, 5, 217, 108, 156, 65
    , 185, 147, 45, 82, 200, 37, 207, 217, 234, 226, 200, 59, 85, 203
    , 155, 232, 95, 67, 36, 231, 186, 154, 188, 135, 255, 222, 25, 
    112, 18, 172, 217, 213, 63, 161, 50, 239, 89, 75, 148, 1, 215, 95
    , 172, 174, 19, 235, 72, 4, 53, 50, 167, 154, 31, 112, 188, 237, 
    162, 38, 241, 127, 112, 157, 225, 50, 113, 168, 94, 135, 166, 104
    , 127, 190, 213, 60, 63, 224, 157, 171, 201, 222, 179, 182, 100, 
    254, 28, 172, 79, 222, 96, 70, 16, 49, 34, 75, 117, 48, 230, 216,
    96, 48, 93, 86, 22, 254, 178, 188, 137, 98, 253, 242, 253, 17, 
    108, 138, 134, 225, 83, 200, 23, 175, 171, 114, 41, 184, 194, 153
    , 236, 180, 41, 202, 104, 198, 206, 163, 100, 147, 141, 67, 134, 
    149, 123, 183, 209, 38, 150, 167, 28, 107, 53, 31, 236, 181, 181,
    77, 217, 216, 66, 111, 101, 217, 7, 32, 74, 193, 181, 124, 9, 
    253, 112, 156, 169, 248, 229, 134, 16, 38, 102, 22, 220, 186, 216
    , 135, 164, 5, 155, 158, 66, 39, 177, 110, 245, 101, 171, 249, 
    215, 17, 243, 150, 175, 189, 145, 204, 73, 115, 73, 233, 172, 199
    , 241, 151, 190, 249, 209, 221, 214, 91, 212, 103, 141, 110, 185,
    202, 79, 67, 78, 155, 116, 3, 53, 220, 1, 186, 191, 113, 194, 72
    , 23, 116, 217, 1, 96, 235, 139, 221, 127, 213, 60, 82, 129, 36, 
    135, 104, 45, 197, 137, 248, 190, 94, 121, 234, 87, 137, 228, 252
    , 199, 13, 1, 221, 28, 134, 128, 230, 217, 52, 97, 244, 206, 81, 
    184, 30, 115, 253, 46, 161, 50, 180, 191, 88, 226, 0, 121, 251, 
    231, 63, 247, 205, 50, 201, 88, 137, 185, 149, 67, 227, 215, 137,
    161, 18, 124, 99, 223, 68, 167, 44, 249, 36, 62, 205, 199, 35, 
    18, 13, 65, 191, 9, 224, 70, 192, 205, 68, 160, 144, 204, 164, 
    232, 19, 228, 209, 130, 24, 117, 96, 236, 112, 201, 70, 100, 123,
    71, 90, 25, 79, 254, 95, 28, 66, 216, 159, 188, 87, 228, 254, 
    145, 214, 50, 125, 233, 110, 94, 207, 33, 37, 89, 226, 145, 228, 
    85, 120, 36, 93, 151, 28, 172, 185, 30, 171, 32, 11, 133, 52, 99,
    187, 86, 199, 112, 208, 180, 215, 41, 17, 85, 13, 215, 195, 133,
    3, 187, 248, 202, 183, 104, 170, 40, 102, 122, 120, 91, 28, 217,
    16, 45, 209, 248, 145, 236, 190, 11, 202, 58, 148, 93, 91, 186, 
    251, 22, 151, 116, 113, 117, 226, 149, 27, 193, 7, 9, 117, 120, 
    108, 183, 211, 254, 239, 195, 60, 8, 90, 132, 42, 53, 233, 115, 
    79, 165, 157, 52, 73, 107, 24, 99, 92, 147, 23, 91, 220, 52, 35, 
    152, 171, 27, 190, 162, 168, 22, 230, 126, 208, 162, 19, 202, 176
    , 32, 223, 201, 234, 124, 65, 238, 112, 129, 227, 130, 45, 51, 
    184, 136, 186, 186, 111, 41, 161, 5, 147, 187, 228, 76, 138, 234,
    91, 10, 62, 103, 225, 114, 194, 194, 109, 211, 108, 108, 58, 175
    , 128, 117, 209, 11, 51, 252, 189, 190, 183, 109, 221, 126, 214, 
    155, 147, 254, 131, 152, 42, 53, 16, 200, 16, 127, 194, 77, 26, 
    137, 200, 63, 137, 128, 119, 159, 147, 151, 238, 41, 255, 124, 
    186, 129, 170, 187, 170, 198, 179, 144, 120, 123, 117, 164, 58, 
    117, 167, 6, 211, 206, 49, 141, 215, 2, 83, 108, 191, 120, 35, 30
    , 114, 68, 23, 251, 65, 225
};

const uint8_t RadioTapTest::expected_packet5[] = {
    0, 0, 14, 0, 0, 128, 10, 0, 0, 0, 0, 7, 0, 5, 136, 65, 0, 0, 76, 158, 255, 127, 13, 247, 144, 162, 218, 245, 28, 56, 84, 4, 166, 180, 209, 35, 208, 207, 0, 0, 105, 29, 0, 32, 1, 0, 0, 0, 170, 170, 3, 0, 0, 0, 8, 0, 69, 16, 0, 100, 217, 93, 64, 0, 64, 6, 220, 39, 192, 168, 1, 245, 192, 168, 1, 185, 0, 22, 132, 209, 139, 84, 229, 243, 73, 225, 122, 44, 128, 24, 14, 36, 163, 203, 0, 0, 1, 1, 8, 10, 0, 95, 217, 190, 0, 30, 133, 52, 220, 143, 231, 158, 151, 126, 243, 67, 163, 172, 214, 109, 192, 190, 238, 160, 95, 63, 206, 71, 230, 59, 143, 105, 105, 172, 142, 15, 17, 139, 55, 70, 232, 71, 84, 12, 235, 224, 159, 132, 178, 117, 5, 43, 177, 190, 152, 170
};

TEST_F(RadioTapTest, DefaultConstructor) {
    RadioTap radio;
    EXPECT_TRUE((radio.flags() & RadioTap::FCS) != 0);
    EXPECT_EQ(Utils::mhz_to_channel(radio.channel_freq()), 1);
    EXPECT_EQ(radio.channel_type(), 0xa0U);
    EXPECT_EQ(radio.tsft(), 0U);
    EXPECT_EQ(radio.dbm_signal(), -50);
    EXPECT_EQ(radio.antenna(), 0);
    EXPECT_EQ(radio.rx_flags(), 0);
}

TEST_F(RadioTapTest, ConstructorFromBuffer) {
    RadioTap radio(expected_packet, sizeof(expected_packet));
    EXPECT_EQ(radio.version(), 0);
    EXPECT_EQ(radio.length(), 32);
    EXPECT_EQ(radio.rate(), 0xc);
    EXPECT_EQ(radio.flags(), 0x10);
    
    EXPECT_TRUE((radio.present() & RadioTap::TSTF) != 0);
    EXPECT_TRUE((radio.present() & RadioTap::RATE) != 0);
    EXPECT_TRUE((radio.present() & RadioTap::DBM_SIGNAL) != 0);
    EXPECT_TRUE((radio.present() & RadioTap::ANTENNA) != 0);
    EXPECT_TRUE((radio.present() & RadioTap::CHANNEL_PLUS) != 0);
    
    EXPECT_TRUE((radio.flags() & RadioTap::FCS) != 0);
    EXPECT_THROW(radio.channel_type(), field_not_present);
    EXPECT_THROW(radio.channel_freq(), field_not_present);
    EXPECT_EQ(radio.tsft(), 616089172U);
    EXPECT_EQ(radio.dbm_signal(), -38);
    EXPECT_EQ(radio.dbm_noise(), -96);
    EXPECT_EQ(radio.antenna(), 2);
}

TEST_F(RadioTapTest, ConstructorFromBuffer1) {
    RadioTap radio(expected_packet1, sizeof(expected_packet1));
    EXPECT_EQ(radio.version(), 0);
    EXPECT_EQ(radio.length(), 26);
    EXPECT_EQ(radio.rate(), 2);
    EXPECT_EQ(radio.flags(), 0x10);
    EXPECT_TRUE((radio.flags() & RadioTap::FCS) != 0);
    EXPECT_EQ(radio.antenna(), 1);
    EXPECT_TRUE(radio.find_pdu<Dot11Beacon>() != NULL);
}

TEST_F(RadioTapTest, ConstructorFromBuffer2) {
    RadioTap radio(expected_packet2, sizeof(expected_packet2));
    
    EXPECT_TRUE((radio.present() & RadioTap::RATE) != 0);
    EXPECT_TRUE((radio.present() & RadioTap::CHANNEL) != 0);
    EXPECT_TRUE((radio.present() & RadioTap::DBM_SIGNAL) != 0);
    EXPECT_TRUE((radio.present() & RadioTap::ANTENNA) != 0);
    EXPECT_TRUE((radio.present() & RadioTap::RX_FLAGS) != 0);
    
    EXPECT_EQ(radio.version(), 0);
    EXPECT_EQ(radio.length(), 34);
    EXPECT_EQ(radio.rate(), 0x12);
    EXPECT_EQ(radio.flags(), 0x02);
    EXPECT_EQ(radio.dbm_signal(), -71);
    EXPECT_EQ(radio.channel_type(), 192);
    EXPECT_EQ(radio.channel_freq(), 2447);
    EXPECT_EQ(radio.antenna(), 0);
    EXPECT_TRUE(radio.find_pdu<Dot11QoSData>() != NULL);
}

TEST_F(RadioTapTest, ConstructorFromBuffer3) {
    RadioTap radio(expected_packet3, sizeof(expected_packet3));
    EXPECT_TRUE((radio.present() & RadioTap::RATE) != 0);
    EXPECT_TRUE((radio.present() & RadioTap::CHANNEL) != 0);
    EXPECT_TRUE((radio.present() & RadioTap::DBM_SIGNAL) != 0);
    EXPECT_TRUE((radio.present() & RadioTap::ANTENNA) != 0);
    EXPECT_TRUE((radio.present() & RadioTap::RX_FLAGS) != 0);

    EXPECT_EQ(0, radio.antenna());
    EXPECT_EQ(-75, radio.dbm_signal());

    EXPECT_TRUE(radio.find_pdu<ARP>() != NULL);
}

TEST_F(RadioTapTest, ConstructorFromBuffer4) {
    RadioTap radio(expected_packet4, sizeof(expected_packet4));
    EXPECT_TRUE((radio.present() & RadioTap::TSTF) != 0);
    EXPECT_TRUE((radio.present() & RadioTap::DBM_SIGNAL) != 0);
    EXPECT_TRUE((radio.present() & RadioTap::CHANNEL) != 0);
    EXPECT_TRUE((radio.present() & RadioTap::ANTENNA) != 0);
    EXPECT_TRUE((radio.present() & RadioTap::RX_FLAGS) != 0);
    EXPECT_TRUE((radio.present() & RadioTap::MCS) != 0);

    EXPECT_EQ(2076020709598ULL, radio.tsft());
    EXPECT_EQ(0, radio.rx_flags());
    EXPECT_EQ(0, radio.antenna());
    EXPECT_EQ(-70, radio.dbm_signal());
    EXPECT_EQ(2412, radio.channel_freq());
    EXPECT_EQ(0x0480, radio.channel_type());
    EXPECT_EQ(0x27, radio.mcs().known);
    EXPECT_EQ(0x00, radio.mcs().flags);
    EXPECT_EQ(0x01, radio.mcs().mcs);

    EXPECT_TRUE(radio.find_pdu<Dot11Data>() != NULL);
}

TEST_F(RadioTapTest, ConstructorFromBuffer5) {
    RadioTap radio(expected_packet5, sizeof(expected_packet5));
    EXPECT_TRUE((radio.present() & RadioTap::DATA_RETRIES) != 0);
    EXPECT_TRUE((radio.present() & RadioTap::TX_FLAGS) != 0);
    EXPECT_TRUE((radio.present() & RadioTap::MCS) != 0);

    EXPECT_EQ(0, radio.data_retries());
    EXPECT_EQ(0, radio.tx_flags());
    EXPECT_EQ(0x07, radio.mcs().known);
    EXPECT_EQ(0x00, radio.mcs().flags);
    EXPECT_EQ(0x05, radio.mcs().mcs);
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

TEST_F(RadioTapTest, SerializationWorksFine) {
    const uint8_t expected[] = {
        0, 0, 26, 0, 43, 72, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 108,
        9, 160, 0, 206, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 170, 170, 3, 0, 0, 0, 136, 142,
        1, 3, 0, 95, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 55, 43, 4, 210
    };
    RadioTap radio = RadioTap() / Dot11Data() / SNAP() / RSNEAPOL();
    RadioTap::serialization_type buffer = radio.serialize();
    EXPECT_EQ(
        RadioTap::serialization_type(expected, expected + sizeof(expected)),
        buffer
    );
}

#endif // TINS_HAVE_DOT11
