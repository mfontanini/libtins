#include "config.h"

#ifdef TINS_HAVE_DOT11

#include <gtest/gtest.h>
#include <cstring>
#include <string>
#include <stdint.h>
#include "crypto.h"
#include "arp.h"
#include "dot11/dot11_data.h"

using namespace Tins;

class WEPDecryptTest : public testing::Test {
public:
    static const uint8_t expected_packet[];
};

// packet taken from aircrack's site.

const uint8_t WEPDecryptTest::expected_packet[] = {
    8, 66, 0, 0, 255, 255, 255, 255, 255, 255, 0, 18, 191, 18, 50, 41, 
    0, 13, 84, 161, 160, 76, 224, 123, 205, 210, 58, 0, 197, 228, 176, 
    195, 234, 135, 161, 205, 155, 75, 35, 247, 7, 96, 17, 234, 15, 141, 
    137, 251, 20, 68, 48, 171, 27, 11, 244, 76, 43, 50, 130, 40, 129, 37, 
    30, 61, 8, 41, 145, 93, 88, 55, 194, 210, 247, 237, 236, 134, 182, 
    216, 85, 225, 102, 139, 93, 178, 214, 154
};

TEST_F(WEPDecryptTest, Decrypt1) {
    Dot11Data dot11(expected_packet, sizeof(expected_packet));
    Crypto::WEPDecrypter decrypter;
    decrypter.add_password("00:12:bf:12:32:29", "\x1f\x1f\x1f\x1f\x1f");
    
    ASSERT_TRUE(decrypter.decrypt(dot11));
    
    ARP* arp = dot11.find_pdu<ARP>();
    ASSERT_TRUE(arp != NULL);
    EXPECT_EQ(arp->sender_hw_addr(), "00:0e:a6:6b:fb:69");
    EXPECT_EQ(arp->target_hw_addr(), "00:00:00:00:00:00");
    EXPECT_EQ(arp->sender_ip_addr(), "172.16.0.1");
    EXPECT_EQ(arp->target_ip_addr(), "172.16.0.240");
    
    decrypter.add_password("00:12:bf:12:32:29", "\x1f\x1f\x1f\x1f\x1e");
    EXPECT_FALSE(decrypter.decrypt(dot11));
}

#endif // TINS_HAVE_DOT11
