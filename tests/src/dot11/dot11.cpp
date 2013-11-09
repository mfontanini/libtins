#include "config.h"

#ifdef HAVE_DOT11

#include <gtest/gtest.h>
#include "tests/dot11.h"
#include "utils.h"

using namespace std;
using namespace Tins;

typedef Dot11::address_type address_type;

class Dot11Test : public testing::Test {
public:
    static const address_type empty_addr, hwaddr;
    static const uint8_t expected_packet[];
};

const address_type Dot11Test::empty_addr,
                   Dot11Test::hwaddr("72:91:34:fa:de:ad");


const uint8_t Dot11Test::expected_packet[] = { 
    53, 1, 79, 35, 0, 1, 2, 3, 4, 5
};

TEST_F(Dot11Test, DefaultConstructor) {
    Dot11 dot11;
    EXPECT_EQ(dot11.protocol(), 0);
    EXPECT_EQ(dot11.type(), 0);
    EXPECT_EQ(dot11.subtype(), 0);
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

TEST_F(Dot11Test, CopyConstructor) {
    Dot11 dot1(expected_packet, sizeof(expected_packet));
    Dot11 dot2(dot1);
    test_equals(dot1, dot2);
}

TEST_F(Dot11Test, CopyAssignmentOperator) {
    Dot11 dot1(expected_packet, sizeof(expected_packet));
    Dot11 dot2;
    dot2 = dot1;
    test_equals(dot1, dot2);
}

// type="Control", subtype=3, proto=1, FCfield="to-DS", ID=0x234f, addr1="00:01:02:03:04:05"
TEST_F(Dot11Test, ConstructorFromBuffer) {
    Dot11 dot11(expected_packet, sizeof(expected_packet));
    EXPECT_EQ(dot11.protocol(), 1);
    EXPECT_EQ(dot11.type(), Dot11::CONTROL);
    EXPECT_EQ(dot11.subtype(), 3);
    EXPECT_EQ(dot11.to_ds(), 1);
    EXPECT_EQ(dot11.from_ds(), 0);
    EXPECT_EQ(dot11.more_frag(), 0);
    EXPECT_EQ(dot11.retry(), 0);
    EXPECT_EQ(dot11.power_mgmt(), 0);
    EXPECT_EQ(dot11.wep(), 0);
    EXPECT_EQ(dot11.order(), 0);
    EXPECT_EQ(dot11.duration_id(), 0x234f);
    EXPECT_EQ(dot11.addr1(), "00:01:02:03:04:05");
}

TEST_F(Dot11Test, SrcAddrConstructor) {
    Dot11 dot11(hwaddr);
    EXPECT_EQ(dot11.addr1(), hwaddr);
}

TEST_F(Dot11Test, Protocol) {
    Dot11 dot11;
    dot11.protocol(1);
    EXPECT_EQ(dot11.protocol(), 1);
}

TEST_F(Dot11Test, Type) {
    Dot11 dot11;
    dot11.type(Dot11::CONTROL);
    EXPECT_EQ(dot11.type(), Dot11::CONTROL);
}

TEST_F(Dot11Test, Subtype) {
    Dot11 dot11;
    dot11.subtype(Dot11::QOS_DATA_DATA);
    EXPECT_EQ(dot11.subtype(), Dot11::QOS_DATA_DATA);
}

TEST_F(Dot11Test, ToDS) {
    Dot11 dot11;
    dot11.to_ds(true);
    EXPECT_EQ(dot11.to_ds(), true);
}

TEST_F(Dot11Test, FromDS) {
    Dot11 dot11;
    dot11.from_ds(true);
    EXPECT_EQ(dot11.from_ds(), true);
}

TEST_F(Dot11Test, MoreFrag) {
    Dot11 dot11;
    dot11.more_frag(1);
    EXPECT_EQ(dot11.more_frag(), 1);
}

TEST_F(Dot11Test, Retry) {
    Dot11 dot11;
    dot11.retry(1);
    EXPECT_EQ(dot11.retry(), 1);
}

TEST_F(Dot11Test, PowerMGMT) {
    Dot11 dot11;
    dot11.power_mgmt(1);
    EXPECT_EQ(dot11.power_mgmt(), 1);
}

TEST_F(Dot11Test, WEP) {
    Dot11 dot11;
    dot11.wep(1);
    EXPECT_EQ(dot11.wep(), 1);
}

TEST_F(Dot11Test, Order) {
    Dot11 dot11;
    dot11.order(1);
    EXPECT_EQ(dot11.order(), 1);
}

TEST_F(Dot11Test, DurationID) {
    Dot11 dot11;
    dot11.duration_id(0x7163);
    EXPECT_EQ(dot11.duration_id(), 0x7163);
}

TEST_F(Dot11Test, Addr1) {
    Dot11 dot11;
    dot11.addr1(hwaddr);
    EXPECT_EQ(dot11.addr1(), hwaddr);
}

TEST_F(Dot11Test, AddTaggedOption) {
    Dot11 dot11;
    dot11.add_option(Dot11::option(Dot11::SSID, hwaddr.begin(), hwaddr.end()));
    const Dot11::option *option;
    ASSERT_TRUE((option = dot11.search_option(Dot11::SSID)));
    EXPECT_EQ(option->data_size(), hwaddr.size());
    EXPECT_EQ(option->option(), Dot11::SSID);
    EXPECT_TRUE(std::equal(hwaddr.begin(), hwaddr.end(), option->data_ptr()));
}

TEST_F(Dot11Test, Serialize) {
    Dot11 pdu(expected_packet, sizeof(expected_packet));
    PDU::serialization_type buffer = pdu.serialize();
    ASSERT_EQ(sizeof(expected_packet), buffer.size());
    EXPECT_TRUE(std::equal(buffer.begin(), buffer.end(), expected_packet));
}

#endif // HAVE_DOT11
