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
    '\x03', '\x04', '\x05', '\x06', '\x07', '\x00', '\x00'
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

TEST_F(Dot11DataTest, ClonePDU) {
    Dot11Data dot1(expected_packet, sizeof(expected_packet));
    std::auto_ptr<Dot11Data> dot2(dot1.clone_pdu());
    test_equals(dot1, *dot2);
}

TEST_F(Dot11DataTest, FromBytes) {
    std::auto_ptr<PDU> dot11(Dot11::from_bytes(expected_packet, sizeof(expected_packet)));
    ASSERT_TRUE(dot11.get());
    const Dot11Data *inner = dot11->find_inner_pdu<Dot11Data>();
    ASSERT_TRUE(inner);
    test_equals_expected(*inner);
}

