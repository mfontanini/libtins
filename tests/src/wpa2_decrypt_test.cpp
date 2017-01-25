#include "config.h"

#if defined(TINS_HAVE_DOT11) && defined(TINS_HAVE_WPA2_DECRYPTION)

#include <gtest/gtest.h>
#include <cstring>
#include <string>
#include <stdint.h>
#include "crypto.h"
#include "radiotap.h"
#include "dot11/dot11_data.h"
#include "udp.h"
#include "tcp.h"

using namespace Tins;

using std::string;
using std::vector;

class WPA2DecryptTest : public testing::Test {
public:
    typedef HWAddress<6> address_type;
    static const uint8_t ccmp_packets[7][652];
    static const uint8_t tkip_packets[7][211];
    static const size_t ccmp_packets_size[], tkip_packets_size[];

    struct handshake {
        handshake(const string& ssid, const address_type& bssid, const address_type& client_hw) 
        : ssid(ssid), bssid(bssid), client_hw(client_hw) {

        }

        string ssid;
        address_type bssid;
        address_type client_hw;
    };

    struct ap_data {
        ap_data(const string& ssid, const address_type& bssid) 
        : ssid(ssid), bssid(bssid) {

        }

        string ssid;
        address_type bssid;
    };
    
    void check_ccmp_packet5(const PDU& pdu);
    void check_ccmp_packet6(const PDU& pdu);
    
    void check_tkip_packet5(const PDU& pdu);
    void check_tkip_packet6(const PDU& pdu);

    void handshake_captured(const string& ssid, const address_type& bssid, const address_type& client_hw) {
        handshakes_.push_back(handshake(ssid, bssid, client_hw));
    }

    void ap_found(const string& ssid, const address_type& bssid) {
        access_points_.push_back(ap_data(ssid, bssid));
    }

    vector<handshake> handshakes_; 
    vector<ap_data> access_points_; 
};

// packet taken from aircrack's site.

const uint8_t WPA2DecryptTest::ccmp_packets[7][652] = {
    // Beacon
    {0, 0, 24, 0, 142, 88, 0, 0, 16, 2, 108, 9, 160, 0, 96, 0, 0, 42, 0, 0, 71, 123, 147, 9, 128, 0, 0, 0, 255, 255, 255, 255, 255, 255, 0, 12, 65, 130, 178, 85, 0, 12, 65, 130, 178, 85, 128, 252, 134, 225, 42, 28, 1, 0, 0, 0, 100, 0, 17, 4, 0, 7, 67, 111, 104, 101, 114, 101, 114, 1, 8, 130, 132, 139, 150, 36, 48, 72, 108, 3, 1, 1, 5, 4, 0, 1, 0, 0, 42, 1, 2, 47, 1, 2, 48, 24, 1, 0, 0, 15, 172, 2, 2, 0, 0, 15, 172, 4, 0, 15, 172, 2, 1, 0, 0, 15, 172, 2, 0, 0, 50, 4, 12, 18, 24, 96, 221, 6, 0, 16, 24, 2, 0, 4, 221, 28, 0, 80, 242, 1, 1, 0, 0, 80, 242, 2, 2, 0, 0, 80, 242, 4, 0, 80, 242, 2, 1, 0, 0, 80, 242, 2, 0, 0, 71, 123, 147, 9},
    // EAPOL keys
    {0, 0, 24, 0, 142, 88, 0, 0, 16, 108, 108, 9, 192, 0, 100, 0, 0, 39, 0, 0, 183, 8, 75, 112, 8, 2, 44, 0, 0, 13, 147, 130, 54, 58, 0, 12, 65, 130, 178, 85, 0, 12, 65, 130, 178, 85, 176, 252, 170, 170, 3, 0, 0, 0, 136, 142, 2, 3, 0, 117, 2, 0, 138, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 62, 142, 150, 125, 172, 217, 96, 50, 76, 172, 91, 106, 167, 33, 35, 91, 245, 123, 148, 151, 113, 200, 103, 152, 159, 73, 208, 78, 212, 124, 105, 51, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 22, 221, 20, 0, 15, 172, 4, 89, 45, 168, 128, 150, 196, 97, 218, 36, 108, 105, 0, 30, 135, 127, 61, 183, 8, 75, 112},
    {0, 0, 24, 0, 142, 88, 0, 0, 16, 108, 108, 9, 192, 0, 100, 0, 0, 56, 0, 0, 138, 11, 46, 247, 8, 1, 44, 0, 0, 12, 65, 130, 178, 85, 0, 13, 147, 130, 54, 58, 0, 12, 65, 130, 178, 85, 144, 1, 170, 170, 3, 0, 0, 0, 136, 142, 2, 3, 0, 117, 2, 1, 10, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 205, 244, 5, 206, 185, 216, 137, 239, 61, 236, 66, 96, 152, 40, 250, 229, 70, 183, 173, 215, 186, 236, 187, 26, 57, 78, 172, 82, 20, 177, 211, 134, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 164, 98, 167, 2, 154, 213, 186, 48, 182, 175, 13, 243, 145, 152, 142, 69, 0, 22, 48, 20, 1, 0, 0, 15, 172, 2, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 2, 0, 0, 138, 11, 46, 247},
    {0, 0, 24, 0, 142, 88, 0, 0, 16, 108, 108, 9, 192, 0, 100, 0, 0, 40, 0, 0, 108, 57, 145, 12, 8, 2, 44, 0, 0, 13, 147, 130, 54, 58, 0, 12, 65, 130, 178, 85, 0, 12, 65, 130, 178, 85, 192, 252, 170, 170, 3, 0, 0, 0, 136, 142, 2, 3, 0, 175, 2, 19, 202, 0, 16, 0, 0, 0, 0, 0, 0, 0, 1, 62, 142, 150, 125, 172, 217, 96, 50, 76, 172, 91, 106, 167, 33, 35, 91, 245, 123, 148, 151, 113, 200, 103, 152, 159, 73, 208, 78, 212, 124, 105, 51, 245, 123, 148, 151, 113, 200, 103, 152, 159, 73, 208, 78, 212, 124, 105, 52, 207, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 125, 10, 246, 223, 81, 233, 156, 222, 122, 24, 116, 83, 240, 249, 53, 55, 0, 80, 207, 167, 44, 222, 53, 178, 193, 226, 49, 146, 85, 128, 106, 179, 100, 23, 159, 217, 103, 48, 65, 185, 165, 147, 159, 161, 162, 1, 13, 42, 199, 148, 226, 81, 104, 5, 95, 121, 77, 220, 31, 223, 174, 53, 33, 244, 68, 107, 253, 17, 218, 152, 52, 95, 84, 61, 246, 206, 25, 157, 248, 254, 72, 248, 205, 209, 122, 220, 168, 123, 244, 87, 17, 24, 60, 73, 109, 65, 170, 12, 108, 57, 145, 12},
    {0, 0, 24, 0, 142, 88, 0, 0, 16, 108, 108, 9, 192, 0, 100, 0, 0, 56, 0, 0, 239, 69, 111, 112, 8, 1, 44, 0, 0, 12, 65, 130, 178, 85, 0, 13, 147, 130, 54, 58, 0, 12, 65, 130, 178, 85, 160, 1, 170, 170, 3, 0, 0, 0, 136, 142, 2, 3, 0, 95, 2, 3, 10, 0, 16, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 187, 163, 189, 251, 207, 222, 43, 197, 55, 80, 157, 113, 242, 236, 209, 0, 0, 239, 69, 111, 112},
    // DHCP
    {0, 0, 24, 0, 142, 88, 0, 0, 16, 108, 108, 9, 192, 0, 100, 0, 0, 57, 0, 0, 44, 168, 148, 39, 8, 65, 44, 0, 0, 12, 65, 130, 178, 85, 0, 13, 147, 130, 54, 58, 255, 255, 255, 255, 255, 255, 176, 1, 1, 0, 0, 32, 0, 0, 0, 0, 126, 204, 246, 10, 193, 221, 255, 176, 71, 150, 195, 11, 161, 156, 146, 198, 18, 30, 128, 3, 144, 245, 239, 74, 121, 190, 64, 178, 90, 240, 84, 27, 111, 77, 28, 231, 39, 8, 194, 149, 207, 88, 25, 69, 140, 24, 213, 31, 100, 86, 122, 124, 197, 255, 133, 231, 166, 139, 35, 138, 51, 94, 68, 68, 247, 222, 12, 94, 239, 114, 29, 159, 219, 13, 81, 68, 3, 209, 201, 6, 70, 21, 35, 62, 252, 226, 75, 65, 109, 83, 140, 136, 132, 94, 70, 13, 41, 99, 14, 218, 114, 151, 253, 219, 181, 102, 172, 10, 5, 249, 33, 31, 191, 36, 57, 154, 21, 169, 21, 17, 4, 57, 189, 12, 12, 81, 10, 8, 74, 136, 144, 80, 1, 252, 100, 204, 154, 79, 202, 210, 81, 214, 224, 241, 85, 0, 183, 19, 251, 66, 194, 68, 96, 88, 42, 104, 208, 165, 185, 156, 128, 142, 1, 44, 32, 10, 197, 39, 176, 235, 50, 15, 117, 125, 96, 234, 1, 250, 121, 246, 92, 47, 195, 85, 102, 144, 98, 217, 37, 227, 228, 76, 2, 145, 193, 167, 54, 213, 15, 11, 140, 108, 104, 222, 158, 83, 110, 217, 127, 235, 67, 147, 130, 128, 75, 115, 146, 58, 97, 127, 204, 239, 55, 96, 207, 101, 152, 247, 126, 57, 185, 144, 166, 209, 103, 171, 92, 166, 169, 87, 118, 56, 254, 168, 52, 44, 151, 171, 213, 84, 245, 111, 234, 72, 235, 72, 190, 82, 223, 200, 39, 102, 123, 28, 9, 8, 120, 88, 185, 150, 154, 116, 16, 45, 83, 227, 125, 53, 46, 228, 98, 68, 132, 61, 2, 245, 27, 4, 67, 100, 203, 38, 51, 253, 46, 140, 22, 10, 33, 49, 36, 86, 229, 116, 116, 137, 51, 224, 216, 73, 91, 232, 35, 151, 216, 156, 183, 57, 247, 171, 160, 232, 68, 194, 184, 220, 58, 61, 87, 209, 167, 176, 126, 169, 255, 151, 163, 215, 23, 255, 2, 131, 11, 88, 44, 168, 148, 39},
    // DHCP 
    {0, 0, 24, 0, 142, 88, 0, 0, 16, 108, 108, 9, 192, 0, 100, 0, 0, 41, 0, 0, 190, 202, 53, 174, 8, 66, 44, 0, 0, 13, 147, 130, 54, 58, 0, 12, 65, 130, 178, 85, 0, 12, 65, 130, 178, 83, 240, 252, 1, 0, 0, 32, 0, 0, 0, 0, 119, 49, 71, 116, 105, 136, 85, 205, 132, 196, 180, 119, 142, 132, 254, 142, 107, 185, 34, 64, 127, 182, 129, 59, 98, 183, 207, 159, 167, 27, 149, 169, 74, 170, 255, 149, 57, 187, 223, 19, 162, 165, 18, 63, 50, 153, 100, 9, 247, 29, 231, 199, 141, 125, 148, 9, 183, 62, 244, 101, 50, 254, 146, 237, 122, 204, 152, 151, 197, 153, 31, 122, 219, 59, 230, 26, 123, 231, 100, 31, 201, 119, 175, 228, 12, 189, 233, 235, 65, 148, 46, 143, 49, 144, 44, 76, 79, 143, 126, 163, 219, 81, 122, 250, 102, 252, 179, 97, 116, 151, 128, 138, 29, 29, 171, 64, 93, 233, 245, 44, 35, 244, 249, 140, 160, 198, 188, 44, 120, 38, 104, 52, 107, 70, 115, 34, 239, 117, 195, 195, 20, 193, 85, 224, 22, 142, 205, 27, 155, 34, 62, 19, 32, 199, 200, 3, 59, 253, 188, 180, 177, 41, 150, 247, 98, 199, 127, 43, 239, 236, 116, 51, 19, 185, 188, 97, 156, 151, 64, 144, 20, 103, 61, 23, 210, 236, 235, 23, 216, 116, 121, 14, 191, 150, 210, 255, 195, 230, 167, 53, 254, 207, 35, 28, 18, 209, 240, 112, 156, 181, 151, 30, 81, 215, 6, 225, 106, 153, 48, 91, 102, 171, 115, 62, 46, 70, 255, 39, 183, 219, 199, 73, 97, 127, 92, 18, 153, 206, 150, 200, 7, 153, 82, 151, 34, 170, 177, 94, 178, 149, 202, 164, 210, 176, 112, 106, 73, 213, 101, 14, 195, 115, 168, 153, 217, 52, 76, 130, 116, 159, 226, 247, 234, 238, 6, 250, 141, 149, 133, 208, 40, 106, 172, 130, 187, 114, 216, 250, 124, 47, 4, 227, 198, 97, 125, 69, 2, 219, 87, 123, 79, 150, 116, 187, 239, 120, 236, 199, 185, 96, 30, 112, 233, 237, 179, 28, 46, 149, 102, 253, 150, 133, 179, 71, 7, 119, 201, 39, 196, 106, 251, 100, 195, 201, 47, 109, 227, 158, 27, 70, 207, 241, 222, 179, 225, 220, 189, 224, 97, 134, 11, 150, 127, 235, 224, 222, 110, 141, 224, 0, 167, 126, 72, 155, 185, 162, 128, 141, 120, 39, 165, 5, 211, 222, 20, 11, 129, 222, 142, 149, 130, 136, 106, 105, 118, 135, 9, 220, 180, 196, 117, 66, 82, 215, 186, 107, 252, 85, 41, 131, 238, 85, 233, 197, 228, 157, 49, 42, 57, 52, 40, 235, 240, 208, 248, 180, 26, 153, 227, 223, 33, 247, 236, 162, 226, 253, 63, 144, 199, 157, 164, 56, 185, 19, 8, 197, 210, 129, 90, 177, 16, 119, 165, 208, 244, 247, 253, 121, 10, 51, 15, 215, 140, 231, 51, 198, 168, 11, 54, 126, 135, 145, 13, 161, 192, 119, 16, 184, 30, 235, 23, 133, 20, 247, 139, 30, 235, 110, 211, 13, 39, 76, 4, 153, 83, 236, 215, 52, 107, 75, 188, 73, 74, 60, 203, 80, 194, 127, 7, 65, 225, 195, 139, 166, 176, 22, 151, 54, 204, 159, 5, 254, 82, 145, 230, 163, 254, 191, 206, 29, 198, 78, 198, 232, 238, 247, 104, 245, 100, 67, 108, 90, 88, 177, 136, 32, 28, 76, 108, 195, 172, 251, 121, 158, 23, 52, 33, 118, 205, 239, 50, 163, 118, 65, 150, 69, 109, 152, 70, 31, 235, 102, 126, 254, 209, 228, 148, 203, 137, 34, 20, 69, 141, 180, 177, 154, 155, 35, 101, 1, 78, 207, 67, 117, 29, 104, 9, 244, 3, 220, 131, 61, 190, 202, 53, 174}
};

const uint8_t WPA2DecryptTest::tkip_packets[7][211] = {
    // Beacon
    {0, 0, 18, 0, 46, 72, 0, 0, 0, 2, 108, 9, 160, 0, 221, 3, 0, 0, 128, 0, 0, 0, 255, 255, 255, 255, 255, 255, 0, 27, 17, 210, 27, 235, 0, 27, 17, 210, 27, 235, 128, 178, 129, 97, 244, 15, 0, 0, 0, 0, 100, 0, 17, 0, 0, 4, 78, 79, 68, 79, 1, 4, 130, 132, 139, 150, 3, 1, 1, 5, 4, 0, 1, 0, 0, 48, 20, 1, 0, 0, 15, 172, 2, 1, 0, 0, 15, 172, 2, 1, 0, 0, 15, 172, 2, 0, 0, 221, 9, 0, 3, 127, 1, 1, 0, 32, 255, 127},
    // EAPOL keys
    {0, 0, 18, 0, 46, 72, 0, 0, 0, 22, 108, 9, 160, 0, 220, 3, 0, 0, 8, 2, 212, 0, 148, 12, 109, 143, 147, 136, 0, 27, 17, 210, 27, 235, 0, 27, 17, 210, 27, 235, 208, 178, 170, 170, 3, 0, 0, 0, 136, 142, 1, 3, 0, 95, 2, 0, 137, 0, 32, 0, 0, 0, 0, 0, 0, 0, 1, 22, 241, 158, 216, 151, 86, 157, 129, 160, 33, 116, 210, 24, 191, 213, 40, 130, 92, 75, 22, 151, 22, 95, 91, 248, 168, 188, 129, 250, 161, 255, 151, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 18, 0, 46, 72, 0, 0, 0, 4, 108, 9, 160, 0, 217, 3, 0, 0, 8, 1, 2, 1, 0, 27, 17, 210, 27, 235, 148, 12, 109, 143, 147, 136, 0, 27, 17, 210, 27, 235, 16, 0, 170, 170, 3, 0, 0, 0, 136, 142, 1, 3, 0, 117, 2, 1, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 218, 108, 51, 136, 69, 196, 171, 10, 209, 139, 6, 156, 170, 155, 110, 241, 223, 96, 73, 83, 201, 28, 222, 131, 70, 209, 158, 97, 95, 244, 21, 252, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 50, 47, 4, 90, 85, 130, 65, 3, 66, 245, 143, 64, 146, 174, 5, 207, 0, 22, 48, 20, 1, 0, 0, 15, 172, 2, 1, 0, 0, 15, 172, 2, 1, 0, 0, 15, 172, 2, 0, 0},
    {0, 0, 18, 0, 46, 72, 0, 0, 0, 11, 108, 9, 160, 0, 221, 3, 0, 0, 8, 2, 222, 0, 148, 12, 109, 143, 147, 136, 0, 27, 17, 210, 27, 235, 0, 27, 17, 210, 27, 235, 224, 178, 170, 170, 3, 0, 0, 0, 136, 142, 1, 3, 0, 157, 2, 19, 201, 0, 32, 0, 0, 0, 0, 0, 0, 0, 2, 22, 241, 158, 216, 151, 86, 157, 129, 160, 33, 116, 210, 24, 191, 213, 40, 130, 92, 75, 22, 151, 22, 95, 91, 248, 168, 188, 129, 250, 161, 255, 151, 130, 92, 75, 22, 151, 22, 95, 91, 248, 168, 188, 129, 250, 161, 255, 152, 153, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 200, 127, 245, 65, 126, 225, 15, 125, 92, 194, 78, 120, 25, 55, 127, 161, 0, 62, 177, 70, 196, 230, 213, 190, 41, 84, 138, 229, 131, 21, 227, 143, 239, 152, 60, 170, 35, 101, 197, 230, 223, 109, 20, 24, 167, 6, 69, 155, 148, 212, 94, 203, 228, 45, 8, 69, 76, 47, 148, 124, 147, 146, 141, 231, 60, 11, 189, 254, 170, 106, 73, 190, 229, 99, 202, 247, 41, 133, 130, 175},
    {0, 0, 18, 0, 46, 72, 0, 0, 0, 4, 108, 9, 160, 0, 218, 3, 0, 0, 8, 1, 2, 1, 0, 27, 17, 210, 27, 235, 148, 12, 109, 143, 147, 136, 0, 27, 17, 210, 27, 235, 32, 0, 170, 170, 3, 0, 0, 0, 136, 142, 1, 3, 0, 95, 2, 3, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 178, 109, 5, 166, 193, 94, 143, 159, 84, 66, 114, 244, 166, 240, 46, 1, 0, 0},
    // HTTP data
    {0, 0, 18, 0, 46, 72, 0, 0, 0, 22, 108, 9, 160, 0, 217, 3, 0, 0, 8, 65, 213, 0, 0, 27, 17, 210, 27, 235, 148, 12, 109, 143, 147, 136, 0, 27, 17, 210, 27, 235, 176, 50, 3, 35, 41, 32, 0, 0, 0, 0, 119, 117, 235, 153, 200, 251, 227, 211, 149, 31, 231, 139, 36, 2, 146, 81, 132, 63, 193, 42, 220, 53, 70, 104, 119, 139, 60, 76, 204, 96, 218, 54, 101, 218, 192, 111, 144, 148, 97, 141, 252, 180, 201, 214, 206, 191, 242, 102, 114, 76, 237, 61, 190, 167, 5, 132, 128, 149, 38, 88, 155, 242, 191, 244, 202, 206, 175, 80, 15, 124, 44, 108, 39, 224, 72, 217, 38, 175, 70, 187, 224, 215, 21, 143},
    {0, 0, 18, 0, 46, 72, 0, 0, 0, 22, 108, 9, 160, 0, 218, 3, 0, 0, 8, 65, 213, 0, 0, 27, 17, 210, 27, 235, 148, 12, 109, 143, 147, 136, 0, 27, 17, 210, 27, 235, 192, 50, 3, 35, 42, 32, 0, 0, 0, 0, 168, 193, 175, 225, 65, 44, 37, 61, 12, 214, 29, 41, 12, 133, 137, 107, 94, 99, 138, 118, 238, 219, 83, 108, 25, 181, 195, 163, 47, 193, 177, 2, 53, 152, 111, 13, 169, 165, 84, 127, 163, 139, 194, 120, 242, 195, 144, 28, 13, 162, 53, 143, 220, 86, 40, 217, 222, 38, 69, 206, 184, 38, 125, 79, 210, 85, 1, 129, 2, 190, 26, 109, 243, 227, 75, 176, 160, 86, 158, 124, 41, 153, 11, 0}
};

const size_t WPA2DecryptTest::ccmp_packets_size[] = {
    168, 181, 181, 239, 159, 404, 652
};

const size_t WPA2DecryptTest::tkip_packets_size[] = {
    108, 149, 171, 211, 149, 134, 134
};

void WPA2DecryptTest::check_ccmp_packet5(const PDU& pdu) {
    const UDP* udp = pdu.find_pdu<UDP>();
    ASSERT_TRUE(udp);
    EXPECT_EQ(udp->sport(), 68);
    EXPECT_EQ(udp->dport(), 67);
}

void WPA2DecryptTest::check_ccmp_packet6(const PDU& pdu) {
    const UDP* udp = pdu.find_pdu<UDP>();
    ASSERT_TRUE(udp);
    EXPECT_EQ(udp->sport(), 67);
    EXPECT_EQ(udp->dport(), 68);
}

void WPA2DecryptTest::check_tkip_packet5(const PDU& pdu) {
    const TCP* tcp = pdu.find_pdu<TCP>();
    ASSERT_TRUE(tcp);
    EXPECT_EQ(tcp->sport(), 44934);
    EXPECT_EQ(tcp->dport(), 80);
    EXPECT_EQ(tcp->window(), 1215);
}

void WPA2DecryptTest::check_tkip_packet6(const PDU& pdu) {
    const TCP* tcp = pdu.find_pdu<TCP>();
    ASSERT_TRUE(tcp);
    EXPECT_EQ(tcp->sport(), 44934);
    EXPECT_EQ(tcp->dport(), 80);
    EXPECT_EQ(tcp->window(), 1204);
}

TEST_F(WPA2DecryptTest, DecryptCCMPUsingBeacon) {
    Crypto::WPA2Decrypter decrypter;
    decrypter.add_ap_data("Induction", "Coherer");
    for(size_t i = 0; i < 7; ++i) {
        RadioTap radio(ccmp_packets[i], ccmp_packets_size[i]);
        if(i > 4) {
            ASSERT_TRUE(decrypter.decrypt(radio));
            if(i == 5)
                check_ccmp_packet5(radio);
            else
                check_ccmp_packet6(radio);
        }
        else 
            ASSERT_FALSE(decrypter.decrypt(radio));
    }
}

TEST_F(WPA2DecryptTest, DecryptCCMPWithoutUsingBeacon) {
    Crypto::WPA2Decrypter decrypter;
    decrypter.add_ap_data("Induction", "Coherer", "00:0c:41:82:b2:55");
    for(size_t i = 1; i < 7; ++i) {
        RadioTap radio(ccmp_packets[i], ccmp_packets_size[i]);
        if(i > 4) {
            ASSERT_TRUE(decrypter.decrypt(radio));
            if(i == 5)
                check_ccmp_packet5(radio);
            else
                check_ccmp_packet6(radio);
        }
        else 
            ASSERT_FALSE(decrypter.decrypt(radio));
    }
}

TEST_F(WPA2DecryptTest, DecryptCCMPUsingKey) {
    Crypto::WPA2Decrypter::addr_pair addresses;
    Crypto::WPA2::SessionKeys session_keys;

    {
        Crypto::WPA2Decrypter decrypter;
        decrypter.add_ap_data("Induction", "Coherer", "00:0c:41:82:b2:55");
        for(size_t i = 1; i < 5; ++i) {
            RadioTap radio(ccmp_packets[i], ccmp_packets_size[i]);
            ASSERT_FALSE(decrypter.decrypt(radio));
        }
        const Crypto::WPA2Decrypter::keys_map& keys = decrypter.get_keys();
        ASSERT_EQ(1ULL, keys.size());
        addresses = keys.begin()->first;
        session_keys = keys.begin()->second;
    }

    Crypto::WPA2Decrypter decrypter;
    decrypter.add_decryption_keys(addresses, session_keys);
    for(size_t i = 5; i < 7; ++i) {
        RadioTap radio(ccmp_packets[i], ccmp_packets_size[i]);
        ASSERT_TRUE(decrypter.decrypt(radio));
        if(i == 5)
            check_ccmp_packet5(radio);
        else
            check_ccmp_packet6(radio);
    }

    EXPECT_TRUE(session_keys.uses_ccmp());
}

TEST_F(WPA2DecryptTest, DecryptTKIPUsingBeacon) {
    Crypto::WPA2Decrypter decrypter;
    decrypter.add_ap_data("libtinstest", "NODO");
    for(size_t i = 0; i < 7; ++i) {
        RadioTap radio(tkip_packets[i], tkip_packets_size[i]);
        if(i > 4) {
            ASSERT_TRUE(decrypter.decrypt(radio));
            if(i == 5)
                check_tkip_packet5(radio);
            else
                check_tkip_packet6(radio);
        }
        else 
            ASSERT_FALSE(decrypter.decrypt(radio));
    }
}

TEST_F(WPA2DecryptTest, DecryptTKIPWithoutUsingBeacon) {
    Crypto::WPA2Decrypter decrypter;
    decrypter.add_ap_data("libtinstest", "NODO", "00:1b:11:d2:1b:eb");
    for(size_t i = 1; i < 7; ++i) {
        RadioTap radio(tkip_packets[i], tkip_packets_size[i]);
        if(i > 4) {
            ASSERT_TRUE(decrypter.decrypt(radio));
            if(i == 5)
                check_tkip_packet5(radio);
            else
                check_tkip_packet6(radio);
        }
        else 
            ASSERT_FALSE(decrypter.decrypt(radio));
    }
}

TEST_F(WPA2DecryptTest, DecryptTKIPUsingKey) {
    Crypto::WPA2Decrypter::addr_pair addresses;
    Crypto::WPA2::SessionKeys session_keys;

    {
        Crypto::WPA2Decrypter decrypter;
        decrypter.add_ap_data("libtinstest", "NODO", "00:1b:11:d2:1b:eb");
        for(size_t i = 1; i < 5; ++i) {
            RadioTap radio(tkip_packets[i], tkip_packets_size[i]);
            ASSERT_FALSE(decrypter.decrypt(radio));
        }
        const Crypto::WPA2Decrypter::keys_map& keys = decrypter.get_keys();
        ASSERT_EQ(1ULL, keys.size());
        addresses = keys.begin()->first;
        session_keys = keys.begin()->second;
    }

    Crypto::WPA2Decrypter decrypter;
    decrypter.add_decryption_keys(addresses, session_keys);
    for(size_t i = 5; i < 7; ++i) {
        RadioTap radio(tkip_packets[i], tkip_packets_size[i]);
        ASSERT_TRUE(decrypter.decrypt(radio));
        if(i == 5)
            check_tkip_packet5(radio);
        else
            check_tkip_packet6(radio);
    }

    EXPECT_FALSE(session_keys.uses_ccmp());
}

TEST_F(WPA2DecryptTest, DecryptCCMPAndTKIPUsingBeacon) {
    Crypto::WPA2Decrypter decrypter;
    decrypter.add_ap_data("libtinstest", "NODO");
    decrypter.add_ap_data("Induction", "Coherer");
    for(size_t i = 0; i < 7; ++i) {
        RadioTap radio(ccmp_packets[i], ccmp_packets_size[i]);
        if(i > 4) {
            ASSERT_TRUE(decrypter.decrypt(radio));
            if(i == 5)
                check_ccmp_packet5(radio);
            else
                check_ccmp_packet6(radio);
        }
        else 
            ASSERT_FALSE(decrypter.decrypt(radio));
    }
    for(size_t i = 0; i < 7; ++i) {
        RadioTap radio(tkip_packets[i], tkip_packets_size[i]);
        if(i > 4) {
            ASSERT_TRUE(decrypter.decrypt(radio));
            if(i == 5)
                check_tkip_packet5(radio);
            else
                check_tkip_packet6(radio);
        }
        else 
            ASSERT_FALSE(decrypter.decrypt(radio));
    }
}

TEST_F(WPA2DecryptTest, DecryptCCMPAndTKIPWithoutUsingBeacon) {
    Crypto::WPA2Decrypter decrypter;
    decrypter.add_ap_data("libtinstest", "NODO", "00:1b:11:d2:1b:eb");
    decrypter.add_ap_data("Induction", "Coherer", "00:0c:41:82:b2:55");
    for(size_t i = 1; i < 7; ++i) {
        RadioTap radio(ccmp_packets[i], ccmp_packets_size[i]);
        if(i > 4) {
            ASSERT_TRUE(decrypter.decrypt(radio));
            if(i == 5)
                check_ccmp_packet5(radio);
            else
                check_ccmp_packet6(radio);
        }
        else 
            ASSERT_FALSE(decrypter.decrypt(radio));
    }
    for(size_t i = 1; i < 7; ++i) {
        RadioTap radio(tkip_packets[i], tkip_packets_size[i]);
        if(i > 4) {
            ASSERT_TRUE(decrypter.decrypt(radio));
            if(i == 5)
                check_tkip_packet5(radio);
            else
                check_tkip_packet6(radio);
        }
        else 
            ASSERT_FALSE(decrypter.decrypt(radio));
    }
}

#ifdef TINS_HAVE_WPA2_CALLBACKS

TEST_F(WPA2DecryptTest, HandshakeCapturedCallback) {
    using namespace std::placeholders;

    Crypto::WPA2Decrypter decrypter;
    decrypter.add_ap_data("libtinstest", "NODO", "00:1b:11:d2:1b:eb");
    decrypter.add_ap_data("Induction", "Coherer", "00:0c:41:82:b2:55");
    decrypter.handshake_captured_callback(std::bind(&WPA2DecryptTest::handshake_captured,
                                          this, _1, _2, _3));
    for(size_t i = 1; i < 7; ++i) {
        RadioTap radio(ccmp_packets[i], ccmp_packets_size[i]);
        decrypter.decrypt(radio);
    }
    for(size_t i = 1; i < 7; ++i) {
        RadioTap radio(tkip_packets[i], tkip_packets_size[i]);
        decrypter.decrypt(radio);
    }

    ASSERT_EQ(2U, handshakes_.size());
    handshake hs = handshakes_[0];
    EXPECT_EQ(hs.ssid, "Coherer");
    EXPECT_EQ(address_type("00:0d:93:82:36:3a"), hs.client_hw);
    EXPECT_EQ(address_type("00:0c:41:82:b2:55"), hs.bssid);

    hs = handshakes_[1];
    EXPECT_EQ(hs.ssid, "NODO");
    EXPECT_EQ(address_type("94:0c:6d:8f:93:88"), hs.client_hw);
    EXPECT_EQ(address_type("00:1b:11:d2:1b:eb"), hs.bssid);
}

TEST_F(WPA2DecryptTest, AccessPointFoundCallback) {
    using namespace std::placeholders;

    Crypto::WPA2Decrypter decrypter;
    decrypter.add_ap_data("libtinstest", "NODO");
    decrypter.add_ap_data("Induction", "Coherer");
    decrypter.ap_found_callback(std::bind(&WPA2DecryptTest::ap_found, this, _1, _2));
    for(size_t i = 0; i < 7; ++i) {
        RadioTap radio(ccmp_packets[i], ccmp_packets_size[i]);
        decrypter.decrypt(radio);
    }
    for(size_t i = 0; i < 7; ++i) {
        RadioTap radio(tkip_packets[i], tkip_packets_size[i]);
        decrypter.decrypt(radio);
    }

    ASSERT_EQ(2U, access_points_.size());
    ap_data data = access_points_[0];
    EXPECT_EQ("Coherer", data.ssid);
    EXPECT_EQ(address_type("00:0c:41:82:b2:55"), data.bssid);

    data = access_points_[1];
    EXPECT_EQ("NODO", data.ssid);
    EXPECT_EQ(address_type("00:1b:11:d2:1b:eb"), data.bssid);
}

#endif // TINS_HAVE_WPA2_CALLBACKS

#endif // defined(TINS_HAVE_DOT11) && defined(TINS_HAVE_WPA2_DECRYPTION)
