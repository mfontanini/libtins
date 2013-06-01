#ifndef TINS_DOT11_TEST
#define TINS_DOT11_TEST

#include "dot11/dot11_base.h"

using Tins::Dot11;

typedef Dot11::address_type address_type;

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


#endif // TINS_DOT11_TEST
