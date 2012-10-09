#include <gtest/gtest.h>
#include <algorithm>
#include <memory>
#include <stdint.h>
#include "dot11.h"
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
    '\t', '\x00', 'O', '#', '\x00', '\x01', '\x02', '\x03', '\x04', 
    '\x05', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x02', 
    '\x03', '\x04', '\x05', '\x06', '\x07', '\xda', '\xf1'
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
    std::auto_ptr<Dot11Data> dot2(dot1.clone());
    test_equals(dot1, *dot2);
}

TEST_F(Dot11DataTest, FromBytes) {
    std::auto_ptr<PDU> dot11(Dot11::from_bytes(expected_packet, sizeof(expected_packet)));
    ASSERT_TRUE(dot11.get());
    const Dot11Data *inner = dot11->find_pdu<Dot11Data>();
    ASSERT_TRUE(inner);
    test_equals_expected(*inner);
}


TEST_F(Dot11DataTest, PCAPLoad1) {
    const uint8_t buffer[] = {
        '\x08', 'B', '\xd4', '\x00', '\x00', '$', '!', '\x92', '\xa7', 
        'S', '\x00', '\x1b', '\x11', '\xd2', '\x1b', '\xeb', '\x00', 
        '\x1b', '\x11', '\xd2', '\x1b', '\xeb', '\x90', 'y', '\xa3', 
        '_', '\x00', ' ', '\x00', '\x00', '\x00', '\x00', '\xf0', '\xef', 
        '\xb5', '\xf9', '4', '\xcb', '\x00', ',', 'D', '\xe4', '\xba', 
        '"', '\xa7', '/', '/', 'G', '\x04', '\xd5', 'o', 'N', '\xeb', 
        '6', '[', '\xc3', 'D', 't', 'y', '\xec', '\x84', '\xf2', '`', 
        ' ', 'X', '\x1e', 'p', '\xa2', 'z', '\x02', '\x1a', '7', '\xd2', 
        '\xf2', '\n', '\x1c', '\xc7', 'z', 'D', '\xc4', '\xc4', '\xbc', 
        'G', '_', '\x9f', '\xcf', '\xbc', '\xa2', '\xb7', '\xaf', '\xed', 
        '\xe0', '\xcc', '\xb9', '\x9e', '\x94', ' ', '\xee', 'F', '\x89', 
        '1', '\xab', '\xe7', '\xb8', 'I', '\xaf', '\xc3', '\xf4', '\xc5', 
        '\x95', '\x1c', '\x8d', '\x1a', '\xf8', ':', '\xbd', '\x95', 
        '\xbf', 'y', '\xce', '\xda', 'x', 's', '@', '\xe0', '>', '\xa1', 
        'B', '\x94', '\xd9', '\xb1', '\xa6', '\x17', '\xee', '\xb4', 
        '\x95', 'E'
    };
    Dot11Data dot1(buffer, sizeof(buffer));
    EXPECT_EQ(dot1.addr1(), "00:24:21:92:a7:53");
    EXPECT_EQ(dot1.addr2(), "00:1b:11:d2:1b:eb");
    EXPECT_EQ(dot1.addr3(), "00:1b:11:d2:1b:eb");
    EXPECT_EQ(dot1.wep(), 1);
    EXPECT_EQ(dot1.from_ds(), 1);
    EXPECT_EQ(dot1.frag_num(), 0);
    EXPECT_EQ(dot1.seq_num(), 1945);
    std::auto_ptr<Dot11Data> dot2(dot1.clone());
    test_equals(dot1, *dot2);
}

TEST_F(Dot11DataTest, Serialize) {
    Dot11Data pdu(expected_packet, sizeof(expected_packet));
    PDU::serialization_type buffer = pdu.serialize();
    ASSERT_EQ(sizeof(expected_packet), buffer.size());
    EXPECT_TRUE(std::equal(buffer.begin(), buffer.end(), expected_packet));
}
