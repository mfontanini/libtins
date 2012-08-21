#ifndef TINS_DOT11_TEST
#define TINS_DOT11_TEST

#include "dot11.h"

inline void test_equals(const Tins::Dot11 &dot1, const Tins::Dot11 &dot2) {
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

#endif // TINS_DOT11_TEST
