#include <gtest/gtest.h>
#include <string>
#include "network_interface.h"
#include "utils.h"
#include "macros.h"

using namespace Tins;

class NetworkInterfaceTest : public ::testing::Test {
public:
    static const std::string iface_name, iface_addr;
};

#ifdef BSD
const std::string NetworkInterfaceTest::iface_name("lo0"),
                  NetworkInterfaceTest::iface_addr("");
#elif defined(WIN32)
// modify me on every windows environment :D
const std::string NetworkInterfaceTest::iface_name("{INSERT-SOME-INTERFACE-NAME}"),
                  NetworkInterfaceTest::iface_addr("");
#else
const std::string NetworkInterfaceTest::iface_name("lo"),
                  NetworkInterfaceTest::iface_addr("");
#endif

TEST_F(NetworkInterfaceTest, ConstructorFromString) {
    // just test this doesn't throw
    NetworkInterface iface(iface_name);
    
    try {
        NetworkInterface iface("ishallnotexist");
        ASSERT_TRUE(false);
    }
    catch(...) {
        
    }
}

TEST_F(NetworkInterfaceTest, ConstructorFromIp) {
    NetworkInterface iface(IPv4Address("127.0.0.1"));
    EXPECT_EQ(iface.name(), iface_name);
}

TEST_F(NetworkInterfaceTest, Id) {
    NetworkInterface iface(iface_name);
    EXPECT_TRUE(iface.id() != 0);
}

TEST_F(NetworkInterfaceTest, Info) {
    NetworkInterface iface(iface_name);
    NetworkInterface::Info info(iface.addresses());
    // assuming it's like this
    EXPECT_EQ(info.ip_addr, "127.0.0.1");
    EXPECT_EQ(info.netmask, "255.0.0.0");
}

TEST_F(NetworkInterfaceTest, EqualsOperator) {
    NetworkInterface iface1(iface_name), iface2(iface_name);
    EXPECT_EQ(iface1, iface2);
}

TEST_F(NetworkInterfaceTest, DistinctOperator) {
    NetworkInterface iface1(iface_name), iface2;
    EXPECT_NE(iface1, iface2);
}


