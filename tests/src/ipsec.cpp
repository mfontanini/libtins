#include <gtest/gtest.h>
#include <algorithm>
#include "ipsec.h"
#include "ethernetII.h"
#include "rawpdu.h"

using namespace Tins;

class IPSecAHTest : public testing::Test {
public:
    static const uint8_t expected_packet[];
};

class IPSecESPTest : public testing::Test {
public:
    static const uint8_t expected_packet[];
};

const uint8_t whole_packet[] = {
    194, 1, 87, 117, 0, 0, 194, 0, 87, 117, 0, 0, 8, 0, 69, 0, 0, 180, 
    0, 107, 0, 0, 255, 51, 166, 169, 10, 0, 0, 1, 10, 0, 0, 2, 50, 4, 0, 
    0, 129, 121, 183, 5, 0, 0, 0, 1, 39, 207, 192, 165, 228, 61, 105, 
    179, 114, 142, 197, 176, 72, 218, 194, 228, 0, 0, 0, 1, 7, 65, 190, 
    127, 138, 222, 64, 192, 43, 216, 26, 238, 15, 80, 111, 44, 70, 220, 
    189, 73, 172, 173, 48, 187, 90, 9, 112, 128, 195, 214, 136, 212, 
    155, 95, 34, 92, 232, 113, 132, 209, 249, 248, 173, 98, 103, 250, 
    26, 162, 24, 151, 15, 209, 53, 182, 153, 55, 36, 84, 68, 95, 107, 
    211, 204, 25, 177, 95, 183, 1, 178, 52, 217, 74, 7, 236, 107, 252, 
    45, 61, 19, 53, 179, 1, 53, 102, 180, 116, 215, 195, 37, 155, 127, 
    228, 185, 34, 165, 191, 163, 208, 144, 200, 154, 155, 109, 106, 183, 
    242, 186, 17, 255, 199, 163, 135, 182, 5, 88, 122, 36, 168, 41, 156, 
    125, 137, 194, 33, 153, 161, 189, 0
};

const uint8_t IPSecAHTest::expected_packet[] = {
    50, 4, 0, 0, 129, 121, 183, 5, 0, 0, 0, 1, 39, 207, 192, 165, 228, 
    61, 105, 179, 114, 142, 197, 176, 72, 218, 194, 228, 0, 0, 0, 1, 7, 
    65, 190, 127, 138, 222, 64, 192, 43, 216, 26, 238, 15, 80, 111, 44, 
    70, 220, 189, 73, 172, 173, 48, 187, 90, 9, 112, 128, 195, 214, 136, 
    212, 155, 95, 34, 92, 232, 113, 132, 209, 249, 248, 173, 98, 103, 
    250, 26, 162, 24, 151, 15, 209, 53, 182, 153, 55, 36, 84, 68, 95, 
    107, 211, 204, 25, 177, 95, 183, 1, 178, 52, 217, 74, 7, 236, 107, 
    252, 45, 61, 19, 53, 179, 1, 53, 102, 180, 116, 215, 195, 37, 155, 
    127, 228, 185, 34, 165, 191, 163, 208, 144, 200, 154, 155, 109, 106, 
    183, 242, 186, 17, 255, 199, 163, 135, 182, 5, 88, 122, 36, 168, 41, 
    156, 125, 137, 194, 33, 153, 161, 189, 0
};

const uint8_t IPSecESPTest::expected_packet[] = {
    72, 218, 194, 228, 0, 0, 0, 1, 7, 65, 190, 127, 138, 222, 64, 192, 
    43, 216, 26, 238, 15, 80, 111, 44, 70, 220, 189, 73, 172, 173, 48, 
    187, 90, 9, 112, 128, 195, 214, 136, 212, 155, 95, 34, 92, 232, 113, 
    132, 209, 249, 248, 173, 98, 103, 250, 26, 162, 24, 151, 15, 209, 
    53, 182, 153, 55, 36, 84, 68, 95, 107, 211, 204, 25, 177, 95, 183, 
    1, 178, 52, 217, 74, 7, 236, 107, 252, 45, 61, 19, 53, 179, 1, 53, 
    102, 180, 116, 215, 195, 37, 155, 127, 228, 185, 34, 165, 191, 163, 
    208, 144, 200, 154, 155, 109, 106, 183, 242, 186, 17, 255, 199, 163, 
    135, 182, 5, 88, 122, 36, 168, 41, 156, 125, 137, 194, 33, 153, 161, 
    189, 0
};

// AH

TEST_F(IPSecAHTest, DefaultConstructor) {
    IPSecAH ipsec;
    EXPECT_EQ(0, ipsec.next_header());
    EXPECT_EQ(2, ipsec.length());
    EXPECT_EQ(0, ipsec.spi());
    EXPECT_EQ(0, ipsec.seq_number());
    EXPECT_EQ(4, ipsec.icv().size());
}

TEST_F(IPSecAHTest, EthPacket) {
    EthernetII eth(whole_packet, sizeof(whole_packet));
    EXPECT_TRUE(eth.find_pdu<IPSecAH>());
    EXPECT_TRUE(eth.find_pdu<IPSecESP>());
    EXPECT_TRUE(eth.find_pdu<RawPDU>());
}

TEST_F(IPSecAHTest, ConstructorFromBuffer) {
    IPSecAH ipsec(expected_packet, sizeof(expected_packet));
    const char *icv_ptr = "\x27\xcf\xc0\xa5\xe4\x3d\x69\xb3\x72\x8e\xc5\xb0";
    EXPECT_EQ(0x32, ipsec.next_header());
    EXPECT_EQ(4, ipsec.length());
    EXPECT_EQ(0x8179b705, ipsec.spi());
    EXPECT_EQ(1, ipsec.seq_number());
    ASSERT_EQ(12, ipsec.icv().size());
    EXPECT_EQ(ipsec.icv(), byte_array(icv_ptr, icv_ptr + 12));
    EXPECT_TRUE(ipsec.find_pdu<IPSecESP>());
    EXPECT_TRUE(ipsec.find_pdu<RawPDU>());
}

TEST_F(IPSecAHTest, Serialize) {
    IPSecAH ipsec(expected_packet, sizeof(expected_packet));
    EXPECT_EQ(
        byte_array(expected_packet, expected_packet + sizeof(expected_packet)),
        ipsec.serialize()
    );
}

TEST_F(IPSecAHTest, NextHeader) {
    IPSecAH ipsec;
    ipsec.next_header(0x73);
    EXPECT_EQ(0x73, ipsec.next_header());
}

TEST_F(IPSecAHTest, Length) {
    IPSecAH ipsec;
    ipsec.length(0x73);
    EXPECT_EQ(0x73, ipsec.length());
}

TEST_F(IPSecAHTest, SPI) {
    IPSecAH ipsec;
    ipsec.spi(0x73a625fa);
    EXPECT_EQ(0x73a625fa, ipsec.spi());
}

TEST_F(IPSecAHTest, SeqNumber) {
    IPSecAH ipsec;
    ipsec.seq_number(0x73a625fa);
    EXPECT_EQ(0x73a625fa, ipsec.seq_number());
}

TEST_F(IPSecAHTest, ICV) {
    IPSecAH ipsec;
    byte_array data;
    data.push_back(0x29);
    data.push_back(0x52);
    data.push_back(0x9a);
    data.push_back(0x73);
    ipsec.icv(data);
    EXPECT_EQ(data, ipsec.icv());
}



// IPSecESP

TEST_F(IPSecESPTest, DefaultConstructor) {
    IPSecESP ipsec;
    EXPECT_EQ(0, ipsec.spi());
    EXPECT_EQ(0, ipsec.seq_number());
}

TEST_F(IPSecESPTest, ConstructorFromBuffer) {
    IPSecESP ipsec(expected_packet, sizeof(expected_packet));
    EXPECT_EQ(0x48dac2e4, ipsec.spi());
    EXPECT_EQ(1, ipsec.seq_number());
    EXPECT_TRUE(ipsec.find_pdu<RawPDU>());
}

TEST_F(IPSecESPTest, SPI) {
    IPSecESP ipsec;
    ipsec.spi(0x73a625fa);
    EXPECT_EQ(0x73a625fa, ipsec.spi());
}

TEST_F(IPSecESPTest, SeqNumber) {
    IPSecESP ipsec;
    ipsec.seq_number(0x73a625fa);
    EXPECT_EQ(0x73a625fa, ipsec.seq_number());
}

TEST_F(IPSecESPTest, Serialize) {
    IPSecESP ipsec(expected_packet, sizeof(expected_packet));
    EXPECT_EQ(
        byte_array(expected_packet, expected_packet + sizeof(expected_packet)),
        ipsec.serialize()
    );
}
