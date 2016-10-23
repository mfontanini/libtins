#include <gtest/gtest.h>
#include <cstring>
#include <string>
#include <algorithm>
#include <stdint.h>
#include "tcp.h"
#include "ip.h"
#include "ethernetII.h"
#include "utils.h"

using namespace std;
using namespace Tins;

class TCPTest : public testing::Test {
public:
    static const uint8_t expected_packet[], checksum_packet[],
                            partial_packet[];
    
    void test_equals(const TCP& tcp1, const TCP& tcp2);
};

const uint8_t TCPTest::expected_packet[] = {
    127, 77, 79, 29, 241, 218, 229, 70, 95, 174, 209, 35, 208, 2, 113, 
    218, 0, 0, 31, 174, 2, 4, 152, 250, 8, 10, 79, 210, 58, 203, 137, 254, 
    18, 52, 3, 3, 122, 4, 2, 5, 10, 0, 1, 2, 3, 4, 5, 6, 7, 0, 0, 0
};

// Ethernet + IP + TCP
const uint8_t TCPTest::checksum_packet[] = {
    10, 128, 57, 251, 101, 187, 76, 128, 147, 141, 144, 65, 8, 0, 69, 0, 0, 
    60, 152, 189, 64, 0, 64, 6, 0, 19, 10, 0, 0, 54, 198, 41, 209, 140, 180, 
    207, 1, 187, 114, 130, 185, 186, 0, 0, 0, 0, 160, 2, 114, 16, 44, 228, 0, 
    0, 2, 4, 5, 180, 4, 2, 8, 10, 3, 81, 33, 7, 0, 0, 0, 0, 1, 3, 3, 7
};

const uint8_t TCPTest::partial_packet[] = {
    142, 210, 0, 80, 60, 158, 102, 111, 10, 2, 46, 161, 80, 24, 0, 229, 247, 192, 0, 0
};


TEST_F(TCPTest, DefaultConstructor) {
    TCP tcp;
    EXPECT_EQ(tcp.dport(), 0);
    EXPECT_EQ(tcp.sport(), 0);
    EXPECT_EQ(tcp.pdu_type(), PDU::TCP);
}

TEST_F(TCPTest, ChecksumCheck) {
    EthernetII pkt1(checksum_packet, sizeof(checksum_packet)); 
    const TCP& tcp1 = pkt1.rfind_pdu<TCP>();
    uint16_t checksum = tcp1.checksum();
    
    PDU::serialization_type buffer = pkt1.serialize();
    EXPECT_EQ(
        TCP::serialization_type(
            checksum_packet, 
            checksum_packet + sizeof(checksum_packet)
        ),
        buffer
    );

    EthernetII pkt2(&buffer[0], (uint32_t)buffer.size());
    const TCP& tcp2 = pkt2.rfind_pdu<TCP>();
    EXPECT_EQ(checksum, tcp2.checksum());
    EXPECT_EQ(tcp1.checksum(), tcp2.checksum());
    
}

TEST_F(TCPTest, CopyConstructor) {
    TCP tcp1(0x6d1f, 0x78f2);
    TCP tcp2(tcp1);
    test_equals(tcp1, tcp2);
}

TEST_F(TCPTest, CopyAssignmentOperator) {
    TCP tcp1(0x6d1f, 0x78f2);
    TCP tcp2 = tcp1;
    test_equals(tcp1, tcp2);
}

TEST_F(TCPTest, NestedCopy) {
    TCP* nested_tcp = new TCP(0x6d1f, 0x78f2);
    TCP tcp1(0x6d1f, 0x78f2);
    tcp1.inner_pdu(nested_tcp);
    TCP tcp2(tcp1);
    test_equals(tcp1, tcp2);
}

TEST_F(TCPTest, CompleteConstructor) {
    TCP tcp(0x6d1f, 0x78f2);
    EXPECT_EQ(tcp.dport(), 0x6d1f);
    EXPECT_EQ(tcp.sport(), 0x78f2);
}

TEST_F(TCPTest, DPort) {
    TCP tcp;
    tcp.dport(0x5fad);
    EXPECT_EQ(tcp.dport(), 0x5fad);
}

TEST_F(TCPTest, SPort) {
    TCP tcp;
    tcp.sport(0x5fad);
    EXPECT_EQ(tcp.sport(), 0x5fad);
}

TEST_F(TCPTest, Seq) {
    TCP tcp;
    tcp.seq(0x5fad65fb);
    EXPECT_EQ(tcp.seq(), 0x5fad65fbU);
}

TEST_F(TCPTest, AckSeq) {
    TCP tcp;
    tcp.ack_seq(0x5fad65fb);
    EXPECT_EQ(tcp.ack_seq(), 0x5fad65fbU);
}

TEST_F(TCPTest, Window) {
    TCP tcp;
    tcp.window(0x5fad);
    EXPECT_EQ(tcp.window(), 0x5fad);
}

TEST_F(TCPTest, UrgPtr) {
    TCP tcp;
    tcp.urg_ptr(0x5fad);
    EXPECT_EQ(tcp.urg_ptr(), 0x5fad);
}

TEST_F(TCPTest, DataOffset) {
    TCP tcp;
    tcp.data_offset(0xe);
    EXPECT_EQ(tcp.data_offset(), 0xe);
}

TEST_F(TCPTest, SetFlag) {
    TCP tcp;
    tcp.set_flag(TCP::SYN, 1);
    tcp.set_flag(TCP::FIN, 1);
    
    EXPECT_EQ(tcp.get_flag(TCP::SYN), 1);
    EXPECT_EQ(tcp.get_flag(TCP::FIN), 1);
    EXPECT_EQ(tcp.get_flag(TCP::RST), 0);
    EXPECT_EQ(tcp.get_flag(TCP::PSH), 0);
    EXPECT_EQ(tcp.get_flag(TCP::ACK), 0);
    EXPECT_EQ(tcp.get_flag(TCP::URG), 0);
    EXPECT_EQ(tcp.get_flag(TCP::ECE), 0);
    EXPECT_EQ(tcp.get_flag(TCP::CWR), 0);
}

TEST_F(TCPTest, Flags) {
    TCP tcp;
    tcp.set_flag(TCP::SYN, 1);
    tcp.set_flag(TCP::FIN, 1);
    
    EXPECT_EQ(tcp.flags(), (TCP::SYN | TCP::FIN));
    tcp.flags(TCP::PSH | TCP::RST);
    EXPECT_EQ(tcp.flags(), (TCP::PSH | TCP::RST));
}

TEST_F(TCPTest, MSS) {
    TCP tcp;
    tcp.mss(0x456f);
    EXPECT_EQ(0x456f, tcp.mss());
}

TEST_F(TCPTest, WindowScale) {
    TCP tcp;
    tcp.winscale(0x4f);
    EXPECT_EQ(0x4f, tcp.winscale());
}

TEST_F(TCPTest, SackPermitted) {
    TCP tcp;
    tcp.sack_permitted();
    ASSERT_TRUE(tcp.has_sack_permitted());
}

TEST_F(TCPTest, Sack) {
    TCP tcp;
    TCP::sack_type edges;
    edges.push_back(0x13);
    edges.push_back(0x63fa1d7a);
    edges.push_back(0xff1c);
    tcp.sack(edges);
    ASSERT_EQ(edges, tcp.sack());
}

TEST_F(TCPTest, AlternateChecksum) {
    TCP tcp;
    tcp.altchecksum(TCP::CHK_16FLETCHER);
    EXPECT_EQ(TCP::CHK_16FLETCHER, tcp.altchecksum());
}

TEST_F(TCPTest, Timestamp) {
    TCP tcp;
    std::pair<uint32_t, uint32_t> data(0x456fa23d, 0xfa12d345);
    tcp.timestamp(data.first, data.second);
    EXPECT_EQ(tcp.timestamp(), data);
}

void TCPTest::test_equals(const TCP& tcp1, const TCP& tcp2) {
    EXPECT_EQ(tcp1.dport(), tcp2.dport());
    EXPECT_EQ(tcp2.sport(), tcp2.sport());
    EXPECT_EQ(tcp1.seq(), tcp2.seq());
    EXPECT_EQ(tcp1.ack_seq(), tcp2.ack_seq());
    EXPECT_EQ(tcp1.window(), tcp2.window());
    EXPECT_EQ(tcp1.checksum(), tcp2.checksum());
    EXPECT_EQ(tcp1.urg_ptr(), tcp2.urg_ptr());
    EXPECT_EQ(tcp1.data_offset(), tcp2.data_offset());
    EXPECT_EQ(tcp1.inner_pdu() != NULL, tcp2.inner_pdu() != NULL);
}

TEST_F(TCPTest, ConstructorFromBuffer) {
    TCP tcp1(expected_packet, sizeof(expected_packet));
    
    EXPECT_EQ(tcp1.dport(), 0x4f1d);
    EXPECT_EQ(tcp1.sport(), 0x7f4d);
    EXPECT_EQ(tcp1.seq(), 0xf1dae546);
    EXPECT_EQ(tcp1.ack_seq(), 0x5faed123U);
    EXPECT_EQ(tcp1.window(), 0x71da);
    EXPECT_EQ(tcp1.urg_ptr(), 0x1fae);
    EXPECT_EQ(tcp1.data_offset(), 0xd);
    
    EXPECT_EQ(tcp1.timestamp(), (std::pair<uint32_t, uint32_t>(0x4fd23acb, 0x89fe1234)));
    
    EXPECT_TRUE(tcp1.has_sack_permitted());
    
    EXPECT_EQ(tcp1.winscale(), 0x7a);
    
    EXPECT_EQ(tcp1.mss(), 0x98fa);
    
    TCP::sack_type edges = tcp1.sack();
    TCP::sack_type::const_iterator iter = edges.begin();
    ASSERT_EQ(edges.size(), 2U);
    EXPECT_EQ(*iter++, 0x00010203U);
    EXPECT_EQ(*iter++, 0x04050607U); 
    
    PDU::serialization_type buffer = tcp1.serialize();
    
    TCP tcp2(&buffer[0], (uint32_t)buffer.size());
    test_equals(tcp1, tcp2);
}

TEST_F(TCPTest, ConstructorFromPartialBuffer) {
    TCP tcp(partial_packet, sizeof(partial_packet));
    EXPECT_FALSE(tcp.inner_pdu());
}

TEST_F(TCPTest, Serialize) {
    TCP tcp1(expected_packet, sizeof(expected_packet));
    PDU::serialization_type buffer = tcp1.serialize();
    ASSERT_EQ(buffer.size(), sizeof(expected_packet));
    EXPECT_TRUE(std::equal(buffer.begin(), buffer.end(), expected_packet));
}

TEST_F(TCPTest, SpoofedOptions) {
    TCP pdu;
    uint8_t a[] = { 1,2,3,4,5,6 };
    pdu.add_option(
        TCP::option(TCP::SACK, 250, a, a + sizeof(a))
    );
    pdu.add_option(
        TCP::option(TCP::SACK, 250, a, a + sizeof(a))
    );
    pdu.add_option(
        TCP::option(TCP::SACK, 250, a, a + sizeof(a))
    );
    // probably we'd expect it to crash if it's not working, valgrind plx
    EXPECT_EQ(3U, pdu.options().size());
    EXPECT_EQ(pdu.serialize().size(), pdu.size());
}

TEST_F(TCPTest, RemoveOption) {
    TCP tcp(22, 987);
    uint8_t a[] = { 1,2,3,4,5,6 };
    // Add an option
    tcp.mss(1400);
    PDU::serialization_type old_buffer = tcp.serialize();
    
    // Add options and remove them. The serializations before and after should be equal.
    tcp.add_option(TCP::option(TCP::SACK, 250, a, a + sizeof(a)));
    tcp.add_option(TCP::option(TCP::SACK_OK));
    tcp.add_option(TCP::option(TCP::NOP));
    EXPECT_TRUE(tcp.remove_option(TCP::SACK));
    EXPECT_TRUE(tcp.remove_option(TCP::SACK_OK));
    EXPECT_TRUE(tcp.remove_option(TCP::NOP));

    PDU::serialization_type new_buffer = tcp.serialize();
    EXPECT_EQ(old_buffer, new_buffer);
}
