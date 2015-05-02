#include <gtest/gtest.h>
#include <cstring>
#include <string>
#include <stdint.h>
#include "macros.h"
#ifndef _WIN32
    #include <sys/socket.h>
    #ifdef BSD
        #include <net/if_dl.h>
        #include <netinet/in.h>
        #include <net/ethernet.h>
    #endif
#endif
#include "loopback.h"
#include "ip.h"
#include "tcp.h"

using namespace std;
using namespace Tins;

class LoopbackTest : public testing::Test {
public:
    
};

#ifndef _WIN32
TEST_F(LoopbackTest, MatchesResponse) {
    Loopback loop1 = Loopback() / IP("192.168.0.1", "192.168.0.2") / TCP(22, 21);
    loop1.family(PF_INET);
    Loopback loop2 = Loopback() / IP("192.168.0.2", "192.168.0.1") / TCP(21, 22);
    loop2.family(PF_INET);
    PDU::serialization_type buffer = loop2.serialize();
    EXPECT_TRUE(loop1.matches_response(&buffer[0], buffer.size()));
}
#endif // _WIN32
