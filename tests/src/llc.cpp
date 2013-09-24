#include <gtest/gtest.h>
#include <cstring>
#include <string>
#include <stdint.h>

#include "llc.h"

using namespace Tins;
using namespace std;

class LLCTest : public testing::Test {
public:
    static const uint8_t from_buffer_unnumbered[];
    static const uint8_t from_buffer_info[];
    static const uint8_t from_buffer_super[];

    //void test_equals(const IP &ip1, const IP &ip2);
};

const uint8_t LLCTest::from_buffer_info[] = {
    254, 72, 60, 59
};
const uint8_t LLCTest::from_buffer_super[] = {
    75, 25, 5, 58
};
const uint8_t LLCTest::from_buffer_unnumbered[] = {
    170, 23, 207
};


TEST_F(LLCTest, DefaultConstructor) {
	LLC llc;
	EXPECT_EQ(llc.ssap(), 0);
	EXPECT_EQ(llc.dsap(), 0);
    EXPECT_EQ(llc.type(), LLC::INFORMATION);
    EXPECT_EQ(llc.header_size(), 4U);
    EXPECT_EQ(llc.pdu_type(), PDU::LLC);
}

TEST_F(LLCTest, ParamsConstructor) {
	LLC llc(0xAD, 0x16);
	EXPECT_EQ(0xAD, llc.dsap());
	EXPECT_EQ(0x16, llc.ssap());
	EXPECT_EQ(LLC::INFORMATION, llc.type());
	EXPECT_EQ(4U, llc.header_size());
    EXPECT_EQ(PDU::LLC, llc.pdu_type());
}

TEST_F(LLCTest, Group) {
	LLC llc;
	llc.group(true);
	EXPECT_TRUE(llc.group());
	llc.group(false);
	EXPECT_FALSE(llc.group());
}

TEST_F(LLCTest, Dsap) {
	LLC llc;
	llc.dsap(0xaa);
	EXPECT_EQ(llc.dsap(), 0xaa);
	llc.dsap(0x01);
	EXPECT_EQ(llc.dsap(), 0x01);
}

TEST_F(LLCTest, Response) {
	LLC llc;
	llc.response(true);
	EXPECT_TRUE(llc.response());
	llc.response(false);
	EXPECT_FALSE(llc.response());
}

TEST_F(LLCTest, Ssap) {
	LLC llc;
	llc.ssap(0xaa);
	EXPECT_EQ(llc.ssap(), 0xaa);
	llc.ssap(0x01);
	EXPECT_EQ(llc.ssap(), 0x01);
}

TEST_F(LLCTest, Type) {
	LLC llc;
	llc.type(LLC::INFORMATION);
	EXPECT_EQ(llc.type(), LLC::INFORMATION);
	llc.type(LLC::SUPERVISORY);
	EXPECT_EQ(llc.type(), LLC::SUPERVISORY);
	llc.type(LLC::UNNUMBERED);
	EXPECT_EQ(llc.type(), LLC::UNNUMBERED);
}

TEST_F(LLCTest, HeadSize) {
	LLC llc;
	llc.type(LLC::INFORMATION);
	EXPECT_EQ(llc.header_size(), 4U);
	llc.type(LLC::SUPERVISORY);
	EXPECT_EQ(llc.header_size(), 4U);
	llc.type(LLC::UNNUMBERED);
	EXPECT_EQ(llc.header_size(), 3U);
}

TEST_F(LLCTest, SendSeqNumber) {
	LLC llc;
	llc.type(LLC::INFORMATION);
	llc.send_seq_number(18);
	EXPECT_EQ(18, llc.send_seq_number());
	llc.send_seq_number(127);
	EXPECT_EQ(127, llc.send_seq_number());
	llc.type(LLC::SUPERVISORY);
	EXPECT_EQ(0, llc.send_seq_number());
	llc.type(LLC::UNNUMBERED);
	EXPECT_EQ(0, llc.send_seq_number());
}

TEST_F(LLCTest, ReceiveSeqNumber) {
	LLC llc;
	llc.type(LLC::INFORMATION);
	llc.receive_seq_number(18);
	EXPECT_EQ(18, llc.receive_seq_number());
	llc.receive_seq_number(127);
	EXPECT_EQ(127, llc.receive_seq_number());
	llc.type(LLC::SUPERVISORY);
	llc.receive_seq_number(19);
	EXPECT_EQ(19, llc.receive_seq_number());
	llc.receive_seq_number(127);
	EXPECT_EQ(127, llc.receive_seq_number());
	llc.type(LLC::UNNUMBERED);
	EXPECT_EQ(0, llc.receive_seq_number());

}

TEST_F(LLCTest, PollFinal) {
	LLC llc;
	llc.type(LLC::INFORMATION);
	llc.poll_final(true);
	EXPECT_TRUE(llc.poll_final());
	llc.poll_final(false);
	EXPECT_FALSE(llc.poll_final());
	llc.type(LLC::SUPERVISORY);
	llc.poll_final(true);
	EXPECT_TRUE(llc.poll_final());
	llc.poll_final(false);
	EXPECT_FALSE(llc.poll_final());
	llc.type(LLC::UNNUMBERED);
	llc.poll_final(true);
	EXPECT_TRUE(llc.poll_final());
	llc.poll_final(false);
	EXPECT_FALSE(llc.poll_final());
}

TEST_F(LLCTest, SupervisoryFunction) {
	LLC llc;
	llc.type(LLC::INFORMATION);
	EXPECT_EQ(0, llc.supervisory_function());
	llc.type(LLC::SUPERVISORY);
	llc.supervisory_function(LLC::RECEIVE_NOT_READY);
	EXPECT_EQ(LLC::RECEIVE_NOT_READY, llc.supervisory_function());
	llc.supervisory_function(LLC::RECEIVE_READY);
	EXPECT_EQ(LLC::RECEIVE_READY, llc.supervisory_function());
	llc.type(LLC::UNNUMBERED);
	EXPECT_EQ(0, llc.supervisory_function());
}

TEST_F(LLCTest, ModifierFunction) {
	LLC llc;
	llc.type(LLC::INFORMATION);
	EXPECT_EQ(0, llc.modifier_function());
	llc.type(LLC::SUPERVISORY);
	EXPECT_EQ(0, llc.modifier_function());
	llc.type(LLC::UNNUMBERED);
	llc.modifier_function(LLC::TEST);
	EXPECT_EQ(LLC::TEST, llc.modifier_function());
	llc.modifier_function(LLC::XID);
	EXPECT_EQ(LLC::XID, llc.modifier_function());
}

TEST_F(LLCTest, ConstructorFromBuffer) {
	LLC llc(LLCTest::from_buffer_info, 4);
	EXPECT_EQ(LLC::INFORMATION, llc.type());
	EXPECT_EQ(4U, llc.header_size());
	EXPECT_EQ(0xFE, llc.dsap());
	EXPECT_EQ(0x48, llc.ssap());
	EXPECT_FALSE(llc.group());
	EXPECT_FALSE(llc.response());
	EXPECT_TRUE(llc.poll_final());
	EXPECT_EQ(30, llc.send_seq_number());
	EXPECT_EQ(29, llc.receive_seq_number());

	LLC llc_super(LLCTest::from_buffer_super, sizeof(LLCTest::from_buffer_super));
	EXPECT_EQ(4U, llc_super.header_size());
	EXPECT_EQ(0x4B, llc_super.dsap());
	EXPECT_EQ(0x19, llc_super.ssap());
	EXPECT_TRUE(llc_super.group());
	EXPECT_TRUE(llc_super.response());
	EXPECT_FALSE(llc_super.poll_final());
	EXPECT_EQ(29, llc_super.receive_seq_number());
	EXPECT_EQ(LLC::RECEIVE_NOT_READY, llc_super.supervisory_function());

	LLC llc_unnum(LLCTest::from_buffer_unnumbered, sizeof(LLCTest::from_buffer_unnumbered));
	EXPECT_EQ(llc_unnum.header_size(), 3U);
	EXPECT_EQ(llc_unnum.dsap(), 0xaa);
	EXPECT_EQ(llc_unnum.ssap(), 0x17);
	EXPECT_FALSE(llc_unnum.group());
	EXPECT_TRUE(llc_unnum.response());
	EXPECT_FALSE(llc_unnum.poll_final());
	EXPECT_EQ(llc_unnum.modifier_function(), LLC::SABME);
}
