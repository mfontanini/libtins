#include <gtest/gtest.h>
#include <cstring>
#include <string>
#include <stdint.h>
#include "eapol.h"
#include "utils.h"

using namespace std;
using namespace Tins;

class RC4EAPOLTest : public testing::Test {
public:
    
};


TEST_F(RC4EAPOLTest, DefaultConstructor) {
    uint8_t empty_iv[RC4EAPOL::key_iv_size] = { 0 };
    
    RC4EAPOL eapol;
    EXPECT_EQ(1, eapol.version());
    EXPECT_EQ(0x3, eapol.packet_type());
    EXPECT_EQ(EAPOL::RC4, eapol.type());
    EXPECT_EQ(0, eapol.length());
    EXPECT_EQ(0, eapol.key_length());
    EXPECT_EQ(0U, eapol.replay_counter());
    EXPECT_TRUE(std::equal(empty_iv, empty_iv + sizeof(empty_iv), eapol.key_iv()));
    EXPECT_EQ(0, eapol.key_flag());
    EXPECT_EQ(0, eapol.key_index());
    EXPECT_TRUE(std::equal(empty_iv, empty_iv + sizeof(empty_iv), eapol.key_sign()));
    EXPECT_EQ(RC4EAPOL::key_type(), eapol.key());
}

TEST_F(RC4EAPOLTest, Version) {
    RC4EAPOL eapol;
    eapol.version(0x7a);
    EXPECT_EQ(0x7a, eapol.version());
}

TEST_F(RC4EAPOLTest, PacketType) {
    RC4EAPOL eapol;
    eapol.packet_type(0x7a);
    EXPECT_EQ(0x7a, eapol.packet_type());
}

TEST_F(RC4EAPOLTest, Length) {
    RC4EAPOL eapol;
    eapol.length(0x7af2);
    EXPECT_EQ(0x7af2, eapol.length());
}

TEST_F(RC4EAPOLTest, Type) {
    RC4EAPOL eapol;
    eapol.type(0x7a);
    EXPECT_EQ(0x7a, eapol.type());
}

TEST_F(RC4EAPOLTest, KeyLength) {
    RC4EAPOL eapol;
    eapol.key_length(0x7af3);
    EXPECT_EQ(0x7af3, eapol.key_length());
}

TEST_F(RC4EAPOLTest, ReplayCounter) {
    RC4EAPOL eapol;
    eapol.replay_counter(0x7af3d91a1fd3abLL);
    EXPECT_EQ(0x7af3d91a1fd3abULL, eapol.replay_counter());
}

TEST_F(RC4EAPOLTest, KeyIV) {
    uint8_t iv[RC4EAPOL::key_iv_size];
    for(unsigned i = 0; i < RC4EAPOL::key_iv_size; ++i)
        iv[i] = i;
    
    RC4EAPOL eapol;
    eapol.key_iv(iv);
    EXPECT_TRUE(std::equal(iv, iv + sizeof(iv), eapol.key_iv()));
}

TEST_F(RC4EAPOLTest, KeyFlag) {
    RC4EAPOL eapol;
    eapol.key_flag(1);
    EXPECT_EQ(1, eapol.key_flag());
    eapol.key_flag(0);
    EXPECT_EQ(0, eapol.key_flag());
}

TEST_F(RC4EAPOLTest, KeyIndex) {
    RC4EAPOL eapol;
    eapol.key_index(0x7d);
    EXPECT_EQ(0x7d, eapol.key_index());
}

TEST_F(RC4EAPOLTest, KeySign) {
    uint8_t sign[RC4EAPOL::key_sign_size];
    for(unsigned i = 0; i < RC4EAPOL::key_sign_size; ++i)
        sign[i] = i;
    
    RC4EAPOL eapol;
    eapol.key_sign(sign);
    EXPECT_TRUE(std::equal(sign, sign + sizeof(sign), eapol.key_sign()));
}

TEST_F(RC4EAPOLTest, Key) {
    RC4EAPOL eapol;
    uint8_t arr[] = { 1, 9, 2, 0x71, 0x87, 0xfa, 0xdf };
    RC4EAPOL::key_type key(arr, arr + sizeof(arr));
    eapol.key(key);
    EXPECT_EQ(key, eapol.key());
}
