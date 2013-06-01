#ifndef TINS_TEST_DOT11_DATA_H
#define TINS_TEST_DOT11_DATA_H

#include "tests/dot11.h"
#include "dot11/dot11_data.h"

using Tins::Dot11Data;

inline void test_equals(const Dot11Data& b1, const Dot11Data& b2) {
    EXPECT_EQ(b1.addr2(), b2.addr2());
    EXPECT_EQ(b1.addr3(), b2.addr3());
    EXPECT_EQ(b1.addr4(), b2.addr4());
    EXPECT_EQ(b1.frag_num(), b2.frag_num());
    EXPECT_EQ(b1.seq_num(), b2.seq_num());
    
    test_equals(static_cast<const Dot11&>(b1), static_cast<const Dot11&>(b2));
}

inline void test_equals_expected(const Dot11Data &dot11) {
    EXPECT_EQ(dot11.type(), Dot11::DATA);
    EXPECT_EQ(dot11.addr1(), "00:01:02:03:04:05");
    EXPECT_EQ(dot11.addr2(), "01:02:03:04:05:06");
    EXPECT_EQ(dot11.addr3(), "02:03:04:05:06:07");
    EXPECT_EQ(dot11.frag_num(), 0xa);
    EXPECT_EQ(dot11.seq_num(), 0xf1d);
}

inline void test_equals_empty(const Dot11Data &dot11) {
    Dot11::address_type empty_addr;
    
    EXPECT_EQ(dot11.addr1(), empty_addr);
    EXPECT_EQ(dot11.addr2(), empty_addr);
    EXPECT_EQ(dot11.addr3(), empty_addr);
    EXPECT_EQ(dot11.frag_num(), 0);
    EXPECT_EQ(dot11.seq_num(), 0);
}

#endif // TINS_TEST_DOT11_DATA_H
