#include <gtest/gtest.h>
#include <algorithm>
#include <memory>
#include <stdint.h>
#include "dot11.h"
#include "cxxstd.h"
#include "tests/dot11.h"


using namespace std;
using namespace Tins;

typedef Dot11::address_type address_type;

class Dot11DataTest : public testing::Test {
public:
    static const address_type empty_addr, hwaddr;
    static const uint8_t expected_packet[];
};

const uint8_t Dot11DataTest::expected_packet[] = { 
    9, 0, 79, 35, 0, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 6, 2, 3, 4, 5, 6, 7, 
    218, 241
};

TEST_F(Dot11DataTest, Constructor) {
    Dot11Data dot11;
    test_equals_empty(dot11);
}

TEST_F(Dot11DataTest, ConstructorFromBuffer) {
    Dot11Data dot11(expected_packet, sizeof(expected_packet));
    test_equals_expected(dot11);
}

TEST_F(Dot11DataTest, CopyConstructor) {
    Dot11Data dot1(expected_packet, sizeof(expected_packet));
    Dot11Data dot2(dot1);
    test_equals(dot1, dot2);
}

TEST_F(Dot11DataTest, CopyAssignmentOperator) {
    Dot11Data dot1(expected_packet, sizeof(expected_packet));
    Dot11Data dot2;
    dot2 = dot1;
    test_equals(dot1, dot2);
}

TEST_F(Dot11DataTest, FragNum) {
    Dot11Data dot11;
    dot11.frag_num(0x3);
    EXPECT_EQ(0x3, dot11.frag_num());
    EXPECT_EQ(0, dot11.seq_num());
}

TEST_F(Dot11DataTest, SeqNum) {
    Dot11Data dot11;
    dot11.seq_num(0x1f2);
    EXPECT_EQ(0x1f2, dot11.seq_num());
    EXPECT_EQ(0, dot11.frag_num());
}

TEST_F(Dot11DataTest, ClonePDU) {
    Dot11Data dot1(expected_packet, sizeof(expected_packet));
    Internals::smart_ptr<Dot11Data>::type dot2(dot1.clone());
    test_equals(dot1, *dot2);
}

TEST_F(Dot11DataTest, FromBytes) {
    Internals::smart_ptr<PDU>::type dot11(Dot11::from_bytes(expected_packet, sizeof(expected_packet)));
    ASSERT_TRUE(dot11.get());
    const Dot11Data *inner = dot11->find_pdu<Dot11Data>();
    ASSERT_TRUE(inner);
    test_equals_expected(*inner);
}


TEST_F(Dot11DataTest, PCAPLoad1) {
    const uint8_t buffer[] = {
        8, 66, 212, 0, 0, 36, 33, 146, 167, 83, 0, 27, 17, 210, 27, 235, 0, 
        27, 17, 210, 27, 235, 144, 121, 163, 95, 0, 32, 0, 0, 0, 0, 240, 239, 
        181, 249, 52, 203, 0, 44, 68, 228, 186, 34, 167, 47, 47, 71, 4, 213, 
        111, 78, 235, 54, 91, 195, 68, 116, 121, 236, 132, 242, 96, 32, 88, 
        30, 112, 162, 122, 2, 26, 55, 210, 242, 10, 28, 199, 122, 68, 196, 
        196, 188, 71, 95, 159, 207, 188, 162, 183, 175, 237, 224, 204, 185, 
        158, 148, 32, 238, 70, 137, 49, 171, 231, 184, 73, 175, 195, 244, 197, 
        149, 28, 141, 26, 248, 58, 189, 149, 191, 121, 206, 218, 120, 115, 
        64, 224, 62, 161, 66, 148, 217, 177, 166, 23, 238, 180, 149, 69
    };
    Dot11Data dot1(buffer, sizeof(buffer));
    EXPECT_EQ(dot1.addr1(), "00:24:21:92:a7:53");
    EXPECT_EQ(dot1.addr2(), "00:1b:11:d2:1b:eb");
    EXPECT_EQ(dot1.addr3(), "00:1b:11:d2:1b:eb");
    EXPECT_EQ(dot1.wep(), 1);
    EXPECT_EQ(dot1.from_ds(), 1);
    EXPECT_EQ(dot1.frag_num(), 0);
    EXPECT_EQ(dot1.seq_num(), 1945);
    Internals::smart_ptr<Dot11Data>::type dot2(dot1.clone());
    test_equals(dot1, *dot2);
}

TEST_F(Dot11DataTest, Serialize) {
    Dot11Data pdu(expected_packet, sizeof(expected_packet));
    PDU::serialization_type buffer = pdu.serialize();
    ASSERT_EQ(sizeof(expected_packet), buffer.size());
    EXPECT_TRUE(std::equal(buffer.begin(), buffer.end(), expected_packet));
}
