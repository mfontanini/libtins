#include <gtest/gtest.h>
#include <cstring>
#include <string>
#include <stdint.h>
#include "offline_packet_filter.h"
#include "ip.h"
#include "tcp.h"
#include "ethernetII.h"
#include "dot3.h"
#include "sll.h"
#include "llc.h"
#include "udp.h"
#include "rawpdu.h"

using namespace Tins;

class OfflinePacketFilterTest : public testing::Test {
public:
    
};

TEST_F(OfflinePacketFilterTest, CopyConstructor) {
    OfflinePacketFilter filter1("udp and port 111", DataLinkType<EthernetII>());
    OfflinePacketFilter filter2(filter1);
    OfflinePacketFilter filter3("tcp", DataLinkType<RadioTap>());
    filter3 = filter1;
    
    {
        EthernetII pkt = EthernetII() / IP() / UDP(111, 11) / RawPDU("test");
        EXPECT_TRUE(filter1.matches_filter(pkt));
        EXPECT_TRUE(filter2.matches_filter(pkt));
        EXPECT_TRUE(filter3.matches_filter(pkt));
    }
    
    {
        EthernetII pkt = EthernetII() / IP() / TCP(111, 11) / RawPDU("test");
        EXPECT_FALSE(filter1.matches_filter(pkt));
        EXPECT_FALSE(filter2.matches_filter(pkt));
        EXPECT_FALSE(filter3.matches_filter(pkt));
    }
}

TEST_F(OfflinePacketFilterTest, MatchesFilterEthTcp) {
    OfflinePacketFilter filter("ip and port 55", DataLinkType<EthernetII>());
    {
        EthernetII pkt = EthernetII() / IP() / TCP(55, 11) / RawPDU("test");
        EXPECT_TRUE(filter.matches_filter(pkt));
    }
    {
        EthernetII pkt = EthernetII() / IP() / TCP(45, 11) / RawPDU("test");
        EXPECT_FALSE(filter.matches_filter(pkt));
    }
}

TEST_F(OfflinePacketFilterTest, MatchesFilterEth) {
    OfflinePacketFilter filter("ether dst 00:01:02:03:04:05", DataLinkType<EthernetII>());
    {
        EthernetII pkt = EthernetII("00:01:02:03:04:05") / IP() / TCP(55, 11) / RawPDU("test");
        EXPECT_TRUE(filter.matches_filter(pkt));
    }
    {
        EthernetII pkt = EthernetII() / IP() / TCP(45, 11) / RawPDU("test");
        EXPECT_FALSE(filter.matches_filter(pkt));
    }
}

TEST_F(OfflinePacketFilterTest, MatchesFilterSLLTcp) {
    OfflinePacketFilter filter("ip and port 55", DataLinkType<SLL>());
    {
        SLL pkt = SLL() / IP() / TCP(55, 11) / RawPDU("test");
        EXPECT_TRUE(filter.matches_filter(pkt));
    }
    {
        SLL pkt = SLL() / IP() / TCP(45, 11) / RawPDU("test");
        EXPECT_FALSE(filter.matches_filter(pkt));
    }
}
