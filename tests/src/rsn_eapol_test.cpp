#include <gtest/gtest.h>
#include <cstring>
#include <string>
#include <stdint.h>
#include "eapol.h"
#include "snap.h"
#include "utils.h"
#include "ethernetII.h"
#include "rsn_information.h"

using namespace std;
using namespace Tins;

class RSNEAPOLTest : public testing::Test {
public:
    static const uint8_t expected_packet[];
    static const uint8_t eapol_over_snap[];
    static const uint8_t broken_eapol[];
    
    void test_equals(const RSNEAPOL& eapol1, const RSNEAPOL& eapol2);
};

uint8_t empty_iv[RSNEAPOL::key_iv_size] = { 0 };

const uint8_t nonce[RSNEAPOL::nonce_size] = {
    185, 111, 231, 250, 202, 91, 39, 226, 77, 4, 241, 230, 108, 6, 225, 
    155, 179, 58, 107, 36, 180, 57, 187, 228, 222, 217, 10, 204, 209, 51, 
    30, 158
};
const uint8_t mic[RSNEAPOL::mic_size] = {
    177, 186, 172, 85, 150, 74, 189, 48, 86, 133, 101, 42, 178, 38, 117, 
    130
};
const uint8_t key[56] = {
    226, 197, 79, 71, 243, 14, 201, 47, 66, 216, 213, 30, 49, 157, 245, 
    72, 96, 109, 78, 227, 217, 132, 211, 67, 90, 21, 252, 88, 15, 62, 116, 
    96, 64, 145, 16, 96, 239, 177, 67, 248, 253, 182, 10, 54, 203, 164, 
    68, 152, 38, 7, 26, 255, 139, 147, 211, 46
};
const uint8_t rsc[RSNEAPOL::rsc_size] = {
    177, 6
};
const uint8_t id[RSNEAPOL::id_size] = {
    0
};

const uint8_t RSNEAPOLTest::expected_packet[] = {
    1, 3, 0, 151, 2, 19, 202, 0, 16, 0, 0, 0, 0, 0, 0, 0, 2, 185, 111, 
    231, 250, 202, 91, 39, 226, 77, 4, 241, 230, 108, 6, 225, 155, 179, 
    58, 107, 36, 180, 57, 187, 228, 222, 217, 10, 204, 209, 51, 30, 158, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 177, 6, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 177, 186, 172, 85, 150, 74, 189, 48, 
    86, 133, 101, 42, 178, 38, 117, 130, 0, 56, 226, 197, 79, 71, 243, 
    14, 201, 47, 66, 216, 213, 30, 49, 157, 245, 72, 96, 109, 78, 227, 
    217, 132, 211, 67, 90, 21, 252, 88, 15, 62, 116, 96, 64, 145, 16, 96, 
    239, 177, 67, 248, 253, 182, 10, 54, 203, 164, 68, 152, 38, 7, 26, 
    255, 139, 147, 211, 46
};

const uint8_t RSNEAPOLTest::eapol_over_snap[] = {
    170, 170, 3, 0, 0, 0, 136, 142, 2, 3, 0, 95, 2, 0, 138, 0, 16, 0,
    0, 0, 0, 0, 0, 0, 1, 82, 43, 37, 89, 147, 67, 237, 161, 188, 102
    , 113, 206, 250, 93, 102, 154, 119, 17, 84, 225, 191, 146, 83, 
    238, 40, 0, 226, 176, 19, 64, 109, 146, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 216, 
    123, 212, 159
};

const uint8_t RSNEAPOLTest::broken_eapol[] = {
    44, 240, 238, 33, 128, 46, 72, 248, 179, 139, 32, 112, 136, 142, 2, 
    3, 0, 127, 2, 19, 130, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 231, 103, 200, 107, 89, 185, 187, 51, 27, 32, 91, 65, 95, 
    165, 127, 37, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 126, 
    159, 123, 33, 66, 3, 254, 124, 6, 192, 129, 143, 215, 59, 38, 162, 
    0, 24, 221, 22, 0, 15, 172, 1, 1, 0, 237, 214, 169, 68, 84, 98, 24, 
    182, 8, 221, 81, 125, 222, 224, 243, 97, 229, 99, 186, 225, 196, 225, 
    179, 86
};

void RSNEAPOLTest::test_equals(const RSNEAPOL& eapol1, const RSNEAPOL& eapol2) {
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
    EXPECT_EQ(0U, eapol.replay_counter());
    EXPECT_TRUE(std::equal(empty_iv, empty_iv + sizeof(empty_iv), eapol.key_iv()));
    EXPECT_TRUE(std::equal(empty_rsc, empty_rsc + sizeof(empty_rsc), eapol.id()));
    EXPECT_TRUE(std::equal(empty_rsc, empty_rsc + sizeof(empty_rsc), eapol.rsc()));
    EXPECT_EQ(0, eapol.wpa_length());
    EXPECT_TRUE(std::equal(empty_nonce, empty_nonce + sizeof(empty_nonce), eapol.nonce()));
    EXPECT_TRUE(std::equal(empty_iv, empty_iv + sizeof(empty_iv), eapol.mic()));
    EXPECT_EQ(RSNEAPOL::key_type(), eapol.key());
}

TEST_F(RSNEAPOLTest, EAPOLOverSnap) {
    SNAP snap(eapol_over_snap, sizeof(eapol_over_snap));
    EXPECT_TRUE(snap.find_pdu<RSNEAPOL>() != NULL);
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
    EXPECT_EQ(2U, eapol.replay_counter());
    EXPECT_TRUE(std::equal(nonce, nonce + sizeof(nonce), eapol.nonce()));
    EXPECT_TRUE(std::equal(empty_iv, empty_iv + sizeof(empty_iv), eapol.key_iv()));
    EXPECT_TRUE(std::equal(rsc, rsc + sizeof(rsc), eapol.rsc()));
    EXPECT_TRUE(std::equal(id, id + sizeof(id), eapol.id()));
    EXPECT_TRUE(std::equal(mic, mic + sizeof(mic), eapol.mic()));
    ASSERT_EQ(56, eapol.wpa_length());
    RSNEAPOL::key_type key_found = eapol.key();
    ASSERT_EQ(56U, key_found.size());
    EXPECT_TRUE(std::equal(key, key + sizeof(key), key_found.begin()));
}

TEST_F(RSNEAPOLTest, Serialize) {
    RSNEAPOL eapol(expected_packet, sizeof(expected_packet));
    RSNEAPOL::serialization_type buffer = eapol.serialize();
    ASSERT_EQ(sizeof(expected_packet), buffer.size());
    EXPECT_TRUE(std::equal(buffer.begin(), buffer.end(), expected_packet));
}

// This is a test for a packet for which the serialization lacked the WPA key.
// This packet contains a misterious 8 byte field that I can't seem to find 
// on the standard. Wireshark doesn't understand it either. This will currently
// be appended as a RawPDU at the end.
TEST_F(RSNEAPOLTest, SerializeBrokenEapol) {
    EthernetII eapol(broken_eapol, sizeof(broken_eapol));
    RSNEAPOL::serialization_type buffer = eapol.serialize();
    EXPECT_EQ(
        RSNEAPOL::serialization_type(broken_eapol, broken_eapol + sizeof(broken_eapol)),
        buffer
    );
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
    
    RSNEAPOL eapol2(&buffer[0], (uint32_t)buffer.size());
    test_equals(eapol, eapol2);
    
    EXPECT_TRUE(std::equal(buffer.begin(), buffer.end(), expected_packet));
}

TEST_F(RSNEAPOLTest, ReplayCounter) {
    RSNEAPOL eapol;
    eapol.replay_counter(0x7af3d91a1fd3abULL);
    EXPECT_EQ(0x7af3d91a1fd3abULL, eapol.replay_counter());
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
