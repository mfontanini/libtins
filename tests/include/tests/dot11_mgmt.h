#ifndef TINS_DOT11_MGMT_TEST_H
#define TINS_DOT11_MGMT_TEST_H

#include "tests/dot11.h"
#include "dot11/dot11_mgmt.h"

using Tins::Dot11ManagementFrame;

typedef Dot11ManagementFrame::capability_information capability_information;

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


inline void test_equals(const capability_information &info1, const capability_information &info2) {
     EXPECT_EQ(info1.ess(), info2.ess());
     EXPECT_EQ(info1.ibss(), info2.ibss());
     EXPECT_EQ(info1.cf_poll(), info2.cf_poll());
     EXPECT_EQ(info1.cf_poll_req(), info2.cf_poll_req());
     EXPECT_EQ(info1.privacy(), info2.privacy());
     EXPECT_EQ(info1.short_preamble(), info2.short_preamble());
     EXPECT_EQ(info1.pbcc(), info2.pbcc());
     EXPECT_EQ(info1.channel_agility(), info2.channel_agility());
     EXPECT_EQ(info1.spectrum_mgmt(), info2.spectrum_mgmt());
     EXPECT_EQ(info1.qos(), info2.qos());
     EXPECT_EQ(info1.sst(), info2.sst());
     EXPECT_EQ(info1.apsd(), info2.apsd());
     EXPECT_EQ(info1.reserved(), info2.reserved());
     EXPECT_EQ(info1.dsss_ofdm(), info2.dsss_ofdm());
     EXPECT_EQ(info1.delayed_block_ack(), info2.delayed_block_ack());
     EXPECT_EQ(info1.immediate_block_ack(), info2.immediate_block_ack());
}

inline void test_equals_empty(const capability_information &info) {
    EXPECT_EQ(info.ess(), 0);
    EXPECT_EQ(info.ibss(), 0);
    EXPECT_EQ(info.cf_poll(), 0);
    EXPECT_EQ(info.cf_poll_req(), 0);
    EXPECT_EQ(info.privacy(), 0);
    EXPECT_EQ(info.short_preamble(), 0);
    EXPECT_EQ(info.pbcc(), 0);
    EXPECT_EQ(info.channel_agility(), 0);
    EXPECT_EQ(info.spectrum_mgmt(), 0);
    EXPECT_EQ(info.qos(), 0);
    EXPECT_EQ(info.sst(), 0);
    EXPECT_EQ(info.apsd(), 0);
    EXPECT_EQ(info.reserved(), 0);
    EXPECT_EQ(info.dsss_ofdm(), 0);
    EXPECT_EQ(info.delayed_block_ack(), 0);
    EXPECT_EQ(info.immediate_block_ack(), 0);
}

#endif // TINS_DOT11_MGMT_TEST_H
