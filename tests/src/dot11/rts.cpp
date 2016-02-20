#include "config.h"

#ifdef TINS_HAVE_DOT11

#include <gtest/gtest.h>
#include "tests/dot11_control.h"


using namespace std;
using namespace Tins;

typedef Dot11::address_type address_type;

class Dot11RTSTest : public testing::Test {
public:
    static const address_type empty_addr, hwaddr;
    static const uint8_t expected_packet[];
};

const uint8_t Dot11RTSTest::expected_packet[] = { 
    181, 1, 79, 35, 0, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 6
};

void test_equals(const Dot11RTS& dot1, const Dot11RTS& dot2) {
    test_equals(
        static_cast<const Dot11ControlTA&>(dot1),
        static_cast<const Dot11ControlTA&>(dot2)
    );
}

void test_equals_expected(const Dot11RTS& dot11) {
    test_equals_expected(static_cast<const Dot11ControlTA&>(dot11));
    EXPECT_EQ(dot11.subtype(), Dot11::RTS);
}

TEST_F(Dot11RTSTest, Constructor) {
    Dot11RTS dot11;
    test_equals_empty(static_cast<const Dot11ControlTA&>(dot11));
    EXPECT_EQ(dot11.subtype(), Dot11::RTS);
}

TEST_F(Dot11RTSTest, ConstructorFromBuffer) {
    Dot11RTS dot11(expected_packet, sizeof(expected_packet));
    test_equals_expected(dot11);
}

TEST_F(Dot11RTSTest, CopyConstructor) {
    Dot11RTS dot1(expected_packet, sizeof(expected_packet));
    Dot11RTS dot2(dot1);
    test_equals(dot1, dot2);
}

TEST_F(Dot11RTSTest, CopyAssignmentOperator) {
    Dot11RTS dot1(expected_packet, sizeof(expected_packet));
    Dot11RTS dot2;
    dot2 = dot1;
    test_equals(dot1, dot2);
}

TEST_F(Dot11RTSTest, ClonePDU) {
    Dot11RTS dot1(expected_packet, sizeof(expected_packet));
    Internals::smart_ptr<Dot11RTS>::type dot2(dot1.clone());
    test_equals(dot1, *dot2);
}

TEST_F(Dot11RTSTest, FromBytes) {
    Internals::smart_ptr<PDU>::type dot11(Dot11::from_bytes(expected_packet, sizeof(expected_packet)));
    ASSERT_TRUE(dot11.get() != NULL);
    const Dot11RTS* inner = dot11->find_pdu<Dot11RTS>();
    ASSERT_TRUE(inner != NULL);
    test_equals_expected(*inner);
}

TEST_F(Dot11RTSTest, Serialize) {
    Dot11RTS pdu(expected_packet, sizeof(expected_packet));
    PDU::serialization_type buffer = pdu.serialize();
    ASSERT_EQ(sizeof(expected_packet), buffer.size());
    EXPECT_TRUE(std::equal(buffer.begin(), buffer.end(), expected_packet));
}

#endif // TINS_HAVE_DOT11
