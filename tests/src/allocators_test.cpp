#include <gtest/gtest.h>
#include <vector>
#include <algorithm>
#include <stdint.h>
#include "pdu_allocator.h"
#include "ethernetII.h"
#include "snap.h"
#include "sll.h"
#include "dot1q.h"
#include "ip.h"
#include "ipv6.h"


using namespace Tins;

class AllocatorsTest : public testing::Test {
public:
    static const uint8_t link_layer_data_buffer[], ipv4_data_buffer[], ipv6_data_buffer[];
};

const uint8_t AllocatorsTest::link_layer_data_buffer[] = {
    0, 27, 17, 210, 243, 22, 0, 25, 209, 22, 248, 43, 6, 102, 65, 65, 65, 
    65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 
    65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 
    65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 
    65, 65, 65, 65, 65, 65
};

const uint8_t AllocatorsTest::ipv4_data_buffer[] = {
    255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 8, 0, 69, 0, 0, 60, 
    0, 1, 0, 0, 64, 255, 123, 192, 127, 0, 0, 1, 127, 0, 0, 1, 65, 65, 
    65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 
    65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65,
    65, 65, 65, 65
};

const uint8_t AllocatorsTest::ipv6_data_buffer[] = {
    255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 134, 221, 96, 0, 0, 
    0, 0, 40, 250, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 65, 65, 65, 65, 65, 
    65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 
    65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 
    65
};

template<size_t n>
class DummyPDU : public PDU {
public:
    static const PDU::PDUType pdu_flag;

    DummyPDU(const uint8_t* data, uint32_t sz) : buffer(data, data + sz) { }
    DummyPDU* clone() const { return new DummyPDU<n>(*this); }
    uint32_t header_size() const { return (uint32_t)buffer.size(); }
    PDUType pdu_type() const { return pdu_flag; }
    void write_serialization(uint8_t* data, uint32_t, const PDU *) 
    { 
        std::copy(buffer.begin(), buffer.end(), data);
    }
    
    std::vector<uint8_t> buffer;
};

template<size_t n>
const PDU::PDUType DummyPDU<n>::pdu_flag = static_cast<PDU::PDUType>(
    USER_DEFINED_PDU + n
);

TEST_F(AllocatorsTest, LinkLayerPDUs) {
    Allocators::register_allocator<EthernetII, DummyPDU<0> >(1638);
    Allocators::register_allocator<SNAP, DummyPDU<1> >(25);
    Allocators::register_allocator<Dot1Q, DummyPDU<2> >(4562);
    Allocators::register_allocator<SLL, DummyPDU<3> >(16705);
    std::vector<uint8_t> link_layer_data(
        link_layer_data_buffer,
        link_layer_data_buffer + sizeof(link_layer_data_buffer)
    );
    {
        EthernetII pkt(&link_layer_data[0], (uint32_t)link_layer_data.size());
        EXPECT_TRUE(pkt.find_pdu<DummyPDU<0> >() != NULL);
        EXPECT_EQ(pkt.serialize(), link_layer_data);
    }
    {
        SNAP pkt(&link_layer_data[0], (uint32_t)link_layer_data.size());
        EXPECT_TRUE(pkt.find_pdu<DummyPDU<1> >() != NULL);
        EXPECT_EQ(pkt.serialize(), link_layer_data);
    }
    {
        Dot1Q pkt(&link_layer_data[0], (uint32_t)link_layer_data.size());
        EXPECT_TRUE(pkt.find_pdu<DummyPDU<2> >() != NULL);
        EXPECT_EQ(pkt.serialize(), link_layer_data);
    }
    {
        SLL pkt(&link_layer_data[0], (uint32_t)link_layer_data.size());
        EXPECT_TRUE(pkt.find_pdu<DummyPDU<3> >() != NULL);
        EXPECT_EQ(pkt.serialize(), link_layer_data);
    }
}

TEST_F(AllocatorsTest, IP) {
    std::vector<uint8_t> ipv4_data(
        ipv4_data_buffer,
        ipv4_data_buffer + sizeof(ipv4_data_buffer)
    );
    Allocators::register_allocator<IP, DummyPDU<0> >(255);
    EthernetII pkt(&ipv4_data[0], (uint32_t)ipv4_data.size());
    EXPECT_TRUE(pkt.find_pdu<IP>() != NULL);
    EXPECT_TRUE(pkt.find_pdu<DummyPDU<0> >() != NULL);
    EXPECT_EQ(pkt.serialize(), ipv4_data);
}

TEST_F(AllocatorsTest, IPv6) {
    std::vector<uint8_t> ipv6_data(
        ipv6_data_buffer,
        ipv6_data_buffer + sizeof(ipv6_data_buffer)
    );
    Allocators::register_allocator<IPv6, DummyPDU<0> >(250);
    {
        EthernetII pkt(&ipv6_data[0], (uint32_t)ipv6_data.size());
        EXPECT_TRUE(pkt.find_pdu<IPv6>() != NULL);
        EXPECT_TRUE(pkt.find_pdu<DummyPDU<0> >() != NULL);
        EXPECT_EQ(pkt.serialize(), ipv6_data);
    }
}
