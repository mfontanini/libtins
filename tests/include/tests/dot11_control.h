#ifndef TINS_TEST_DOT11_CONTROL_H
#define TINS_TEST_DOT11_CONTROL_H

#include "tests/dot11.h"
#include "dot11/dot11_control.h"

using Tins::Dot11ControlTA;

inline void test_equals(const Dot11ControlTA& b1, const Dot11ControlTA& b2) {
    EXPECT_EQ(b1.target_addr(), b2.target_addr());
    test_equals(static_cast<const Dot11&>(b1), static_cast<const Dot11&>(b2));
}


inline void test_equals_expected(const Dot11ControlTA &dot11) {
    EXPECT_EQ(dot11.target_addr(), "01:02:03:04:05:06");
    EXPECT_EQ(dot11.addr1(), "00:01:02:03:04:05");
}

inline void test_equals_empty(const Dot11ControlTA &dot11) {
    Dot11::address_type empty_addr;
    
    EXPECT_EQ(dot11.target_addr(), empty_addr);
    EXPECT_EQ(dot11.addr1(), empty_addr);
}

#endif // TINS_TEST_DOT11_CONTROL_H
