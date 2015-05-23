#include <gtest/gtest.h>
#include <string>
#include <vector>
#include "network_interface.h"
#include "utils.h"
#include "macros.h"

using namespace Tins;
using namespace std;

class NetworkInterfaceTest : public ::testing::Test {
public:
    static const std::string iface_name, iface_addr;
};

#ifdef BSD
const string NetworkInterfaceTest::iface_name("lo0"),
                  NetworkInterfaceTest::iface_addr("");
#else
const string NetworkInterfaceTest::iface_name("lo"),
                  NetworkInterfaceTest::iface_addr("");
#endif

#ifndef _WIN32
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
#endif // _WIN32

TEST_F(NetworkInterfaceTest, IterateOverInterfaces) {
    vector<NetworkInterface> interfaces = NetworkInterface::all();
    for (size_t i = 0; i < interfaces.size(); ++i) {
        // Expect this interface to be equal to itself
        EXPECT_EQ(interfaces[i], interfaces[i]);
        // We expect to be able to construct the interface from a name 
        // and they should still be equal
        NetworkInterface iface(interfaces[i].name());
        EXPECT_EQ(interfaces[i], iface);
    }
}
