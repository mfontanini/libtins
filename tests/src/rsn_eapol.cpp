#include <gtest/gtest.h>
#include <cstring>
#include <string>
#include <stdint.h>
#include "eapol.h"
#include "utils.h"
#include "rsn_information.h"

using namespace std;
using namespace Tins;

class RSNEAPOLTest : public testing::Test {
public:
    static const uint8_t expected_packet[];
    
    void test_equals(const RSNEAPOL &eapol1, const RSNEAPOL &eapol2);
};

uint8_t empty_iv[RSNEAPOL::key_iv_size] = { 0 };

const uint8_t nonce[RSNEAPOL::nonce_size] = {
    '\xb9', 'o', '\xe7', '\xfa', '\xca', '[', '\'', '\xe2', 'M', '\x04', 
    '\xf1', '\xe6', 'l', '\x06', '\xe1', '\x9b', '\xb3', ':', 'k', '$', 
    '\xb4', '9', '\xbb', '\xe4', '\xde', '\xd9', '\n', '\xcc', '\xd1', 
    '3', '\x1e', '\x9e'
};
const uint8_t mic[RSNEAPOL::mic_size] = {
    '\xb1', '\xba', '\xac', 'U', '\x96', 'J', '\xbd', '0', 'V', 
    '\x85', 'e', '*', '\xb2', '&', 'u', '\x82'
};
const uint8_t key[56] = {
    '\xe2', '\xc5', 'O', 'G', '\xf3', '\x0e', '\xc9', '/', 'B', '\xd8', 
    '\xd5', '\x1e', '1', '\x9d', '\xf5', 'H', '`', 'm', 'N', '\xe3', 
    '\xd9', '\x84', '\xd3', 'C', 'Z', '\x15', '\xfc', 'X', '\x0f', 
    '>', 't', '`', '@', '\x91', '\x10', '`', '\xef', '\xb1', 'C', 
    '\xf8', '\xfd', '\xb6', '\n', '6', '\xcb', '\xa4', 'D', '\x98', 
    '&', '\x07', '\x1a', '\xff', '\x8b', '\x93', '\xd3', '.'
};
const uint8_t rsc[RSNEAPOL::rsc_size] = {
    '\xb1', '\x06'
};
const uint8_t id[RSNEAPOL::id_size] = {
    0
};

const uint8_t RSNEAPOLTest::expected_packet[] = {
    '\x01', '\x03', '\x00', '\x97', '\x02', '\x13', '\xca', '\x00', 
    '\x10', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', 
    '\x02', '\xb9', 'o', '\xe7', '\xfa', '\xca', '[', '\'', '\xe2', 'M', 
    '\x04', '\xf1', '\xe6', 'l', '\x06', '\xe1', '\x9b', '\xb3', ':', 
    'k', '$', '\xb4', '9', '\xbb', '\xe4', '\xde', '\xd9', '\n', '\xcc', 
    '\xd1', '3', '\x1e', '\x9e', '\x00', '\x00', '\x00', '\x00', '\x00', 
    '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', 
    '\x00', '\x00', '\xb1', '\x06', '\x00', '\x00', '\x00', '\x00', '\x00', 
    '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', 
    '\xb1', '\xba', '\xac', 'U', '\x96', 'J', '\xbd', '0', 'V', '\x85', 
    'e', '*', '\xb2', '&', 'u', '\x82', '\x00', '8', '\xe2', '\xc5', 'O', 
    'G', '\xf3', '\x0e', '\xc9', '/', 'B', '\xd8', '\xd5', '\x1e', '1', 
    '\x9d', '\xf5', 'H', '`', 'm', 'N', '\xe3', '\xd9', '\x84', '\xd3', 
    'C', 'Z', '\x15', '\xfc', 'X', '\x0f', '>', 't', '`', '@', '\x91', 
    '\x10', '`', '\xef', '\xb1', 'C', '\xf8', '\xfd', '\xb6', '\n', '6', 
    '\xcb', '\xa4', 'D', '\x98', '&', '\x07', '\x1a', '\xff', '\x8b', 
    '\x93', '\xd3', '.'
};

void RSNEAPOLTest::test_equals(const RSNEAPOL &eapol1, const RSNEAPOL &eapol2) {
    EXPECT_EQ(eapol1.version(), eapol2.version());
    EXPECT_EQ(eapol1.packet_type(), eapol2.packet_type());
    EXPECT_EQ(eapol1.type(), eapol2.type());
    EXPECT_EQ(eapol1.length(), eapol2.length());
    EXPECT_EQ(eapol1.key_length(), eapol2.key_length());
    EXPECT_EQ(eapol1.replay_counter(), eapol2.replay_counter());
    EXPECT_TRUE(std::equal(eapol1.key_iv(), eapol1.key_iv() + RSNEAPOL::key_iv_size, eapol2.key_iv()));
    EXPECT_TRUE(std::equal(eapol1.id(), eapol1.id() + RSNEAPOL::id_size, eapol2.id()));
    EXPECT_TRUE(std::equal(eapol1.rsc(), eapol1.rsc() + RSNEAPOL::rsc_size, eapol2.rsc()));
    EXPECT_EQ(eapol1.wpa_length(), eapol2.wpa_length());
    EXPECT_TRUE(std::equal(eapol1.nonce(), eapol1.nonce() + RSNEAPOL::nonce_size, eapol2.nonce()));
    EXPECT_TRUE(std::equal(eapol1.mic(), eapol1.mic() + RSNEAPOL::mic_size, eapol2.mic()));
    EXPECT_EQ(eapol1.key(), eapol2.key());
}

TEST_F(RSNEAPOLTest, DefaultConstructor) {
    uint8_t empty_nonce[RSNEAPOL::nonce_size] = { 0 };
    uint8_t empty_rsc[RSNEAPOL::rsc_size] = { 0 };
    
    RSNEAPOL eapol;
    EXPECT_EQ(1, eapol.version());
    EXPECT_EQ(0x3, eapol.packet_type());
    EXPECT_EQ(EAPOL::RSN, eapol.type());
    EXPECT_EQ(0, eapol.length());
    EXPECT_EQ(0, eapol.key_length());
    EXPECT_EQ(0, eapol.replay_counter());
    EXPECT_TRUE(std::equal(empty_iv, empty_iv + sizeof(empty_iv), eapol.key_iv()));
    EXPECT_TRUE(std::equal(empty_rsc, empty_rsc + sizeof(empty_rsc), eapol.id()));
    EXPECT_TRUE(std::equal(empty_rsc, empty_rsc + sizeof(empty_rsc), eapol.rsc()));
    EXPECT_EQ(0, eapol.wpa_length());
    EXPECT_TRUE(std::equal(empty_nonce, empty_nonce + sizeof(empty_nonce), eapol.nonce()));
    EXPECT_TRUE(std::equal(empty_iv, empty_iv + sizeof(empty_iv), eapol.mic()));
    EXPECT_EQ(RSNEAPOL::key_type(), eapol.key());
}

TEST_F(RSNEAPOLTest, ConstructorFromBuffer) {
    RSNEAPOL eapol(expected_packet, sizeof(expected_packet));
    EXPECT_EQ(1, eapol.version());
    EXPECT_EQ(3, eapol.packet_type());
    EXPECT_EQ(151, eapol.length());
    EXPECT_EQ(EAPOL::RSN, eapol.type());
    
    EXPECT_EQ(1, eapol.key_t());
    EXPECT_EQ(0, eapol.key_index());
    EXPECT_EQ(1, eapol.install());
    EXPECT_EQ(1, eapol.key_ack());
    EXPECT_EQ(1, eapol.key_mic());
    EXPECT_EQ(1, eapol.secure());
    EXPECT_EQ(0, eapol.error());
    EXPECT_EQ(0, eapol.request());
    EXPECT_EQ(1, eapol.encrypted());
    
    EXPECT_EQ(16, eapol.key_length());
    EXPECT_EQ(2, eapol.replay_counter());
    EXPECT_TRUE(std::equal(nonce, nonce + sizeof(nonce), eapol.nonce()));
    EXPECT_TRUE(std::equal(empty_iv, empty_iv + sizeof(empty_iv), eapol.key_iv()));
    EXPECT_TRUE(std::equal(rsc, rsc + sizeof(rsc), eapol.rsc()));
    EXPECT_TRUE(std::equal(id, id + sizeof(id), eapol.id()));
    EXPECT_TRUE(std::equal(mic, mic + sizeof(mic), eapol.mic()));
    ASSERT_EQ(56, eapol.wpa_length());
    RSNEAPOL::key_type key_found = eapol.key();
    ASSERT_EQ(56, key_found.size());
    EXPECT_TRUE(std::equal(key, key + sizeof(key), key_found.begin()));
}

TEST_F(RSNEAPOLTest, Serialize) {
    RSNEAPOL eapol(expected_packet, sizeof(expected_packet));
    RSNEAPOL::serialization_type buffer = eapol.serialize();
    ASSERT_EQ(sizeof(expected_packet), buffer.size());
    EXPECT_TRUE(std::equal(buffer.begin(), buffer.end(), expected_packet));
}

TEST_F(RSNEAPOLTest, ConstructionTest) {
    RSNEAPOL eapol;
    eapol.version(1);
    eapol.packet_type(3);
    eapol.length(151);
    eapol.key_length(16);
    eapol.replay_counter(2);
    eapol.nonce(nonce);
    eapol.key_iv(empty_iv);
    eapol.rsc(rsc);
    eapol.id(id);
    eapol.mic(mic);
    eapol.key(RSNEAPOL::key_type(key, key + sizeof(key)));
    
    eapol.key_descriptor(2);
    eapol.key_t(1);
    eapol.install(1);
    eapol.key_ack(1);
    eapol.key_mic(1);
    eapol.secure(1);
    eapol.encrypted(1);
    
    RSNEAPOL::serialization_type buffer = eapol.serialize();
    ASSERT_EQ(sizeof(expected_packet), buffer.size());
    
    RSNEAPOL eapol2(&buffer[0], buffer.size());
    test_equals(eapol, eapol2);
    
    EXPECT_TRUE(std::equal(buffer.begin(), buffer.end(), expected_packet));
}

TEST_F(RSNEAPOLTest, ReplayCounter) {
    RSNEAPOL eapol;
    eapol.replay_counter(0x7af3d91a1fd3abLL);
    EXPECT_EQ(0x7af3d91a1fd3abLL, eapol.replay_counter());
}

TEST_F(RSNEAPOLTest, WPALength) {
    RSNEAPOL eapol;
    eapol.wpa_length(0x9af1);
    EXPECT_EQ(0x9af1, eapol.wpa_length());
}

TEST_F(RSNEAPOLTest, KeyIV) {
    RSNEAPOL eapol;
    eapol.key_iv(empty_iv);
    EXPECT_TRUE(std::equal(empty_iv, empty_iv + sizeof(empty_iv), eapol.key_iv()));
}

TEST_F(RSNEAPOLTest, Nonce) {
    RSNEAPOL eapol;
    eapol.nonce(nonce);
    EXPECT_TRUE(std::equal(nonce, nonce + sizeof(nonce), eapol.nonce()));
}

TEST_F(RSNEAPOLTest, Key) {
    RSNEAPOL eapol;
    uint8_t arr[] = { 1, 9, 2, 0x71, 0x87, 0xfa, 0xdf };
    RSNEAPOL::key_type key(arr, arr + sizeof(arr));
    eapol.key(key);
    EXPECT_EQ(key, eapol.key());
}
