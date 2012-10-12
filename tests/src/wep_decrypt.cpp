#include <gtest/gtest.h>
#include <cstring>
#include <string>
#include <stdint.h>
#include "crypto.h"
#include "radiotap.h"
#include "arp.h"

using namespace Tins;

class WEPDecryptTest : public testing::Test {
public:
    static const uint8_t expected_packet[];
};

// packet taken from aircrack's site.

const uint8_t WEPDecryptTest::expected_packet[] = {
    '\x08', 'B', '\x00', '\x00', '\xff', '\xff', '\xff', '\xff', '\xff', 
    '\xff', '\x00', '\x12', '\xbf', '\x12', '2', ')', '\x00', '\r', 'T', 
    '\xa1', '\xa0', 'L', '\xe0', '{', '\xcd', '\xd2', ':', '\x00', '\xc5', 
    '\xe4', '\xb0', '\xc3', '\xea', '\x87', '\xa1', '\xcd', '\x9b', 'K', 
    '#', '\xf7', '\x07', '`', '\x11', '\xea', '\x0f', '\x8d', '\x89', 
    '\xfb', '\x14', 'D', '0', '\xab', '\x1b', '\x0b', '\xf4', 'L', '+', 
    '2', '\x82', '(', '\x81', '%', '\x1e', '=', '\x08', ')', '\x91', ']',
    'X', '7', '\xc2', '\xd2', '\xf7', '\xed', '\xec', '\x86', '\xb6', 
    '\xd8', 'U', '\xe1', 'f', '\x8b', ']', '\xb2', '\xd6', '\x9a'
};

TEST_F(WEPDecryptTest, Decrypt1) {
    Dot11Data dot11(expected_packet, sizeof(expected_packet));
    Crypto::WEPDecrypter decrypter;
    decrypter.add_password("00:12:bf:12:32:29", "\x1f\x1f\x1f\x1f\x1f");
    
    ASSERT_TRUE(decrypter.decrypt(dot11));
    
    ARP *arp = dot11.find_pdu<ARP>();
    ASSERT_TRUE(arp);
    EXPECT_EQ(arp->sender_hw_addr(), "00:0e:a6:6b:fb:69");
    EXPECT_EQ(arp->target_hw_addr(), "00:00:00:00:00:00");
    EXPECT_EQ(arp->sender_ip_addr(), "172.16.0.1");
    EXPECT_EQ(arp->target_ip_addr(), "172.16.0.240");
    
    decrypter.add_password("00:12:bf:12:32:29", "\x1f\x1f\x1f\x1f\x1e");
    EXPECT_FALSE(decrypter.decrypt(dot11));
}
