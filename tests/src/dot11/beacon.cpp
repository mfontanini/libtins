#include <gtest/gtest.h>
#include <algorithm>
#include <memory>
#include <stdint.h>
#include "dot11.h"
#include "tests/dot11.h"


using namespace std;
using namespace Tins;

typedef Dot11::address_type address_type;
typedef Dot11Beacon::channels_type channels_type;

class Dot11BeaconTest : public testing::Test {
public:
    static const address_type empty_addr, hwaddr;
    static const uint8_t expected_packet[];
    static void test_equals_expected(const Dot11Beacon&dot11);
};

const address_type Dot11BeaconTest::empty_addr,
                   Dot11BeaconTest::hwaddr("72:91:34:fa:de:ad");
                   
const uint8_t Dot11BeaconTest::expected_packet[] = { 
    '\x81', '\x01', 'O', '#', '\x00', '\x01', '\x02', '\x03', '\x04', 
    '\x05', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x02', 
    '\x03', '\x04', '\x05', '\x06', '\x07', '\x00', '\x00', '\xfa', 
    '\x01', '\x93', '(', 'A', '#', '\xad', '\x1f', '\xfa', '\x14', 
    '\x95', ' '
};

void Dot11BeaconTest::test_equals_expected(const Dot11Beacon &dot11) {
    EXPECT_EQ(dot11.protocol(), 1);
    EXPECT_EQ(dot11.type(), Dot11::MANAGEMENT);
    EXPECT_EQ(dot11.subtype(), 8);
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
    
    EXPECT_EQ(dot11.timestamp(), 0x1fad2341289301faLL);
    EXPECT_EQ(dot11.interval(), 0x14fa);
    
    const Dot11Beacon::CapabilityInformation &info = dot11.capabilities();
    EXPECT_EQ(info.ess(), 1);
    EXPECT_EQ(info.ibss(), 0);
    EXPECT_EQ(info.cf_poll(), 1);
    EXPECT_EQ(info.cf_poll_req(), 0);
    EXPECT_EQ(info.privacy(), 1);
    EXPECT_EQ(info.short_preamble(), 0);
    EXPECT_EQ(info.pbcc(), 0);
    EXPECT_EQ(info.channel_agility(), 1);
    EXPECT_EQ(info.spectrum_mgmt(), 0);
    EXPECT_EQ(info.qos(), 0);
    EXPECT_EQ(info.sst(), 0);
    EXPECT_EQ(info.apsd(), 0);
    EXPECT_EQ(info.reserved(), 0);
    EXPECT_EQ(info.dsss_ofdm(), 1);
    EXPECT_EQ(info.delayed_block_ack(), 0);
    EXPECT_EQ(info.immediate_block_ack(), 0);
}

void test_equals(const Dot11Beacon& b1, const Dot11Beacon& b2) {
    EXPECT_EQ(b1.addr2(), b2.addr2());
    EXPECT_EQ(b1.addr3(), b2.addr3());
    EXPECT_EQ(b1.addr4(), b2.addr4());
    EXPECT_EQ(b1.frag_num(), b2.frag_num());
    EXPECT_EQ(b1.seq_num(), b2.seq_num());
    EXPECT_EQ(b1.interval(), b2.interval());
    EXPECT_EQ(b1.timestamp(), b2.timestamp());
    
    const Dot11Beacon::CapabilityInformation& info1 = b1.capabilities(),
                                                    info2 = b2.capabilities();
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
    
    test_equals(static_cast<const Dot11&>(b1), static_cast<const Dot11&>(b2));
}
                   
TEST_F(Dot11BeaconTest, DefaultConstructor) {
    Dot11Beacon dot11;
    EXPECT_EQ(dot11.addr2(), empty_addr);
    EXPECT_EQ(dot11.addr3(), empty_addr);
    EXPECT_EQ(dot11.addr4(), empty_addr);
    EXPECT_EQ(dot11.frag_num(), 0);
    EXPECT_EQ(dot11.seq_num(), 0);
    
    const Dot11Beacon::CapabilityInformation& info = dot11.capabilities();
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
    
    EXPECT_EQ(dot11.interval(), 0);
    EXPECT_EQ(dot11.timestamp(), 0);
}

// beacon_interval=0x14fa, timestamp=0x1fad2341289301fa, cap="ESS+CFP+privacy+DSSS-OFDM"
TEST_F(Dot11BeaconTest, ConstructorFromBuffer) {
    Dot11Beacon dot11(expected_packet, sizeof(expected_packet));
    test_equals_expected(dot11);
}

TEST_F(Dot11BeaconTest, CopyConstructor) {
    Dot11Beacon dot1(expected_packet, sizeof(expected_packet));
    Dot11Beacon dot2(dot1);
    test_equals(dot1, dot2);
}

TEST_F(Dot11BeaconTest, CopyAssignmentOperator) {
    Dot11Beacon dot1(expected_packet, sizeof(expected_packet));
    Dot11Beacon dot2;
    dot2 = dot1;
    test_equals(dot1, dot2);
}

TEST_F(Dot11BeaconTest, FromBytes) {
    std::auto_ptr<PDU> dot11(Dot11::from_bytes(expected_packet, sizeof(expected_packet)));
    ASSERT_TRUE(dot11.get());
    const Dot11Beacon *beacon = dot11->find_inner_pdu<Dot11Beacon>();
    ASSERT_TRUE(beacon);
    test_equals_expected(*beacon);
}

TEST_F(Dot11BeaconTest, Timestamp) {
    Dot11Beacon dot11;
    dot11.timestamp(0x1fad2341289301faLL);
    EXPECT_EQ(dot11.timestamp(), 0x1fad2341289301faLL);
}

TEST_F(Dot11BeaconTest, Interval) {
    Dot11Beacon dot11;
    dot11.interval(0x14fa);
    EXPECT_EQ(dot11.interval(), 0x14fa);
}

TEST_F(Dot11BeaconTest, SSID) {
    Dot11Beacon dot11;
    dot11.ssid("libtins");
    EXPECT_EQ(dot11.ssid(), "libtins");
}

TEST_F(Dot11BeaconTest, SupportedRates) {
    Dot11Beacon dot11;
    Dot11Beacon::rates_type rates, found_rates;
    rates.push_back(0.5f);
    rates.push_back(1.0f);
    rates.push_back(5.5f);
    rates.push_back(7.5f);
    dot11.supported_rates(rates);
    found_rates = dot11.supported_rates();
    ASSERT_EQ(rates.size(), found_rates.size());
    EXPECT_TRUE(std::equal(rates.begin(), rates.end(), found_rates.begin()));
}

TEST_F(Dot11BeaconTest, ExtendedSupportedRates) {
    Dot11Beacon dot11;
    Dot11Beacon::rates_type rates, found_rates;
    rates.push_back(0.5f);
    rates.push_back(1.0f);
    rates.push_back(5.5f);
    rates.push_back(7.5f);
    dot11.extended_supported_rates(rates);
    found_rates = dot11.extended_supported_rates();
    ASSERT_EQ(rates.size(), found_rates.size());
    EXPECT_TRUE(std::equal(rates.begin(), rates.end(), found_rates.begin()));
}

TEST_F(Dot11BeaconTest, QOSCapability) {
    Dot11Beacon dot11;
    dot11.qos_capability(0xfa);
    EXPECT_EQ(dot11.qos_capability(), 0xfa);
}

TEST_F(Dot11BeaconTest, PowerCapability) {
    typedef std::pair<uint8_t, uint8_t> power_pair;
    
    Dot11Beacon dot11;
    dot11.power_capability(0xfa, 0xa2);
    power_pair power = dot11.power_capability();
    EXPECT_EQ(power.first, 0xfa);
    EXPECT_EQ(power.second, 0xa2);
}

TEST_F(Dot11BeaconTest, SupportedChannels) {
    Dot11Beacon dot11;
    channels_type channels, output;
    channels.push_back(std::make_pair(13, 19));
    channels.push_back(std::make_pair(67, 159));
    dot11.supported_channels(channels);
    output = dot11.supported_channels();
    ASSERT_EQ(output.size(), channels.size());
    EXPECT_TRUE(std::equal(channels.begin(), channels.end(), output.begin()));
}

TEST_F(Dot11BeaconTest, RequestInformation) {
    Dot11Beacon dot11;
    Dot11Beacon::request_info_type info, found_info;
    info.push_back(10);
    info.push_back(15);
    info.push_back(51);
    info.push_back(42);
    dot11.request_information(info);
    found_info = dot11.request_information();
    ASSERT_EQ(info.size(), found_info.size());
    EXPECT_TRUE(std::equal(info.begin(), info.end(), found_info.begin()));
}

TEST_F(Dot11BeaconTest, FHParameterSet) {
    Dot11Beacon dot11;
    Dot11Beacon::fh_params_set params(0x482f, 67, 42, 0xa1), output;
    dot11.fh_parameter_set(params);
    output = dot11.fh_parameter_set();
    EXPECT_EQ(output.hop_index, params.hop_index);
    EXPECT_EQ(output.hop_pattern, params.hop_pattern);
    EXPECT_EQ(output.hop_set, params.hop_set);
    EXPECT_EQ(output.dwell_time, params.dwell_time);
}

TEST_F(Dot11BeaconTest, DSParameterSet) {
    Dot11Beacon dot11;
    dot11.ds_parameter_set(0x1e);
    EXPECT_EQ(dot11.ds_parameter_set(), 0x1e);
}

TEST_F(Dot11BeaconTest, IBSSParameterSet) {
    Dot11Beacon dot11;
    dot11.ibss_parameter_set(0x1ef3);
    EXPECT_EQ(dot11.ibss_parameter_set(), 0x1ef3);
}

TEST_F(Dot11BeaconTest, IBSS_DFS) {
    Dot11Beacon dot11;
    Dot11Beacon::ibss_dfs_params params, output;
    params.dfs_owner = "00:01:02:03:04:05";
    params.recovery_interval = 0x7f;
    params.channel_map.push_back(std::make_pair(0x8e, 0x92));
    params.channel_map.push_back(std::make_pair(0x02, 0xf2));
    params.channel_map.push_back(std::make_pair(0x3a, 0x53));
    dot11.ibss_dfs(params);
    output = dot11.ibss_dfs();
    EXPECT_EQ(params.dfs_owner, output.dfs_owner);
    EXPECT_EQ(params.recovery_interval, output.recovery_interval);
    ASSERT_EQ(params.channel_map.size(), output.channel_map.size());
    EXPECT_TRUE(std::equal(params.channel_map.begin(), params.channel_map.end(), output.channel_map.begin()));
}

