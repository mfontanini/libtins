#include <gtest/gtest.h>
#include <tins/rawpdu.h>

using namespace Tins;

class RawPDUTest : public testing::Test {
public:
};

TEST_F(RawPDUTest, ConstructFromPayloadType) {
    RawPDU::payload_type payload;
    payload.push_back(0x01);
    payload.push_back(0x02);

    RawPDU raw = RawPDU(payload);
    EXPECT_EQ(payload, raw.payload());

    // The payload should have been copied
    payload.push_back(0x03);
    EXPECT_NE(payload, raw.payload());
}