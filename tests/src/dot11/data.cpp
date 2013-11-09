#include "config.h"

#ifdef HAVE_DOT11

#include <gtest/gtest.h>
#include "tests/dot11_data.h"


using namespace std;
using namespace Tins;

typedef Dot11::address_type address_type;

class Dot11DataTest : public testing::Test {
public:
    static const address_type empty_addr, hwaddr;
    static const uint8_t expected_packet[];
    static const uint8_t from_to_ds00[], from_to_ds10[], from_to_ds01[];
};

const uint8_t Dot11DataTest::expected_packet[] = { 
    9, 0, 79, 35, 0, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 6, 2, 3, 4, 5, 6, 7, 
    218, 241
};

const uint8_t Dot11DataTest::from_to_ds10[] = { 
    8, 2, 58, 1, 0, 37, 156, 116, 149, 146, 0, 24, 248, 245, 194, 198, 
    0, 24, 248, 245, 194, 198, 64, 25, 170, 170, 3, 0, 0, 0, 136, 142, 
    1, 3, 0, 95, 2, 0, 138, 0, 16, 0, 0, 0, 0, 0, 0, 0, 1, 95, 85, 2, 
    186, 64, 12, 215, 130, 122, 211, 219, 9, 59, 133, 92, 160, 245, 149, 
    247, 123, 29, 204, 196, 41, 119, 233, 222, 169, 194, 225, 212, 18, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 60, 112, 49, 29
};

const uint8_t Dot11DataTest::from_to_ds01[] = { 
    8, 1, 202, 0, 0, 24, 248, 245, 194, 198, 0, 37, 156, 116, 149, 146, 0, 
    24, 248, 245, 194, 198, 176, 124, 170, 170, 3, 0, 0, 0, 136, 142, 1, 3, 
    0, 117, 2, 1, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 253, 86, 38, 165, 150, 
    136, 166, 218, 91, 179, 56, 214, 89, 91, 73, 149, 237, 147, 66, 222, 31, 
    21, 190, 114, 129, 179, 254, 230, 168, 219, 145, 48, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 123, 221, 85, 85, 63, 11, 217, 173, 76, 120, 17, 34, 0, 228, 72, 
    107, 0, 22, 48, 20, 1, 0, 0, 15, 172, 2, 1, 0, 0, 15, 172, 4, 1, 0, 0, 
    15, 172, 2, 0, 0, 170, 11, 87, 71
};

const uint8_t Dot11DataTest::from_to_ds00[] = { 
    8, 0, 202, 0, 0, 24, 248, 245, 194, 198, 0, 37, 156, 116, 149, 146, 
    0, 24, 248, 245, 194, 198, 176, 124, 170, 170, 3, 0, 0, 0, 136, 142, 
    1, 3, 0, 117, 2, 1, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 253, 86, 38, 
    165, 150, 136, 166, 218, 91, 179, 56, 214, 89, 91, 73, 149, 237, 147, 
    66, 222, 31, 21, 190, 114, 129, 179, 254, 230, 168, 219, 145, 48, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 123, 221, 85, 85, 63, 11, 217, 173, 76, 120, 
    17, 34, 0, 228, 72, 107, 0, 22, 48, 20, 1, 0, 0, 15, 172, 2, 1, 0, 0, 
    15, 172, 4, 1, 0, 0, 15, 172, 2, 0, 0, 170, 11, 87, 71
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

TEST_F(Dot11DataTest, Source_Dest_BSSID_Address1) {
    Dot11Data data(from_to_ds10, sizeof(from_to_ds10));
    EXPECT_EQ(1, data.from_ds());
    EXPECT_EQ(0, data.to_ds());
    EXPECT_EQ(data.src_addr(), "00:18:f8:f5:c2:c6");
    EXPECT_EQ(data.dst_addr(), "00:25:9c:74:95:92");
    EXPECT_EQ(data.bssid_addr(), "00:18:f8:f5:c2:c6");
}

TEST_F(Dot11DataTest, Source_Dest_BSSID_Address2) {
    Dot11Data data(from_to_ds01, sizeof(from_to_ds01));
    EXPECT_EQ(0, data.from_ds());
    EXPECT_EQ(1, data.to_ds());
    EXPECT_EQ(data.src_addr(), "00:25:9c:74:95:92");
    EXPECT_EQ(data.dst_addr(), "00:18:f8:f5:c2:c6");
    EXPECT_EQ(data.bssid_addr(), "00:18:f8:f5:c2:c6");
}

TEST_F(Dot11DataTest, Source_Dest_BSSID_Address3) {
    Dot11Data data(from_to_ds00, sizeof(from_to_ds00));
    EXPECT_EQ(0, data.from_ds());
    EXPECT_EQ(0, data.to_ds());
    EXPECT_EQ(data.src_addr(), "00:25:9c:74:95:92");
    EXPECT_EQ(data.dst_addr(), "00:18:f8:f5:c2:c6");
    EXPECT_EQ(data.bssid_addr(), "00:18:f8:f5:c2:c6");
}

#endif // HAVE_DOT11
