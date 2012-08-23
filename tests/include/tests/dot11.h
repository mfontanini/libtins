#ifndef TINS_DOT11_TEST
#define TINS_DOT11_TEST

#include "dot11.h"

using Tins::Dot11;
using Tins::Dot11ManagementFrame;

inline void test_equals(const Dot11 &dot1, const Dot11 &dot2) {
    EXPECT_EQ(dot1.protocol(), dot2.protocol());
    EXPECT_EQ(dot1.type(), dot2.type());
    EXPECT_EQ(dot1.subtype(), dot2.subtype());
    EXPECT_EQ(dot1.to_ds(), dot2.to_ds());
    EXPECT_EQ(dot1.from_ds(), dot2.from_ds());
    EXPECT_EQ(dot1.more_frag(), dot2.more_frag());
    EXPECT_EQ(dot1.retry(), dot2.retry());
    EXPECT_EQ(dot1.power_mgmt(), dot2.power_mgmt());
    EXPECT_EQ(dot1.wep(), dot2.wep());
    EXPECT_EQ(dot1.order(), dot2.order());
    EXPECT_EQ(dot1.duration_id(), dot2.duration_id());
    EXPECT_EQ(dot1.addr1(), dot2.addr1());
}

inline void test_equals(const Dot11ManagementFrame& b1, const Dot11ManagementFrame& b2) {
    EXPECT_EQ(b1.addr2(), b2.addr2());
    EXPECT_EQ(b1.addr3(), b2.addr3());
    EXPECT_EQ(b1.addr4(), b2.addr4());
    EXPECT_EQ(b1.frag_num(), b2.frag_num());
    EXPECT_EQ(b1.seq_num(), b2.seq_num());
    
    test_equals(static_cast<const Dot11&>(b1), static_cast<const Dot11&>(b2));
}

inline void test_equals_expected(const Dot11ManagementFrame &dot11) {
    EXPECT_EQ(dot11.protocol(), 1);
    EXPECT_EQ(dot11.type(), Dot11::MANAGEMENT);
    EXPECT_EQ(dot11.to_ds(), 1);
    EXPECT_EQ(dot11.from_ds(), 0);
    EXPECT_EQ(dot11.more_frag(), 0);
    EXPECT_EQ(dot11.retry(), 0);
    EXPECT_EQ(dot11.power_mgmt(), 0);
    EXPECT_EQ(dot11.wep(), 0);
    EXPECT_EQ(dot11.order(), 0);
    EXPECT_EQ(dot11.duration_id(), 0x234f);
    EXPECT_EQ(dot11.addr1(), "00:01:02:03:04:05");
    EXPECT_EQ(dot11.addr2(), "01:02:03:04:05:06");
    EXPECT_EQ(dot11.addr3(), "02:03:04:05:06:07");
}

inline void test_equals_empty(const Dot11 &dot11) {
    Dot11::address_type empty_addr;
    
    EXPECT_EQ(dot11.protocol(), 0);
    EXPECT_EQ(dot11.to_ds(), 0);
    EXPECT_EQ(dot11.from_ds(), 0);
    EXPECT_EQ(dot11.more_frag(), 0);
    EXPECT_EQ(dot11.retry(), 0);
    EXPECT_EQ(dot11.power_mgmt(), 0);
    EXPECT_EQ(dot11.wep(), 0);
    EXPECT_EQ(dot11.order(), 0);
    EXPECT_EQ(dot11.duration_id(), 0);
    EXPECT_EQ(dot11.addr1(), empty_addr);
}

inline void test_equals_empty(const Dot11ManagementFrame &dot11) {
    Dot11::address_type empty_addr;
    
    EXPECT_EQ(dot11.type(), Dot11::MANAGEMENT);
    EXPECT_EQ(dot11.addr2(), empty_addr);
    EXPECT_EQ(dot11.addr3(), empty_addr);
    EXPECT_EQ(dot11.addr4(), empty_addr);
    EXPECT_EQ(dot11.frag_num(), 0);
    EXPECT_EQ(dot11.seq_num(), 0);
    
    test_equals_empty(static_cast<const Dot11 &>(dot11));
}

#endif // TINS_DOT11_TEST
