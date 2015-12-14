#include <gtest/gtest.h>
#include "icmp_extension.h"

using Tins::ICMPExtension;

class ICMPExtensionTest : public testing::Test {
public:

};

TEST_F(ICMPExtensionTest, ConstructorFromBuffer) {
    const uint8_t input[] = { 0, 8, 1, 1, 24, 150, 1, 1 };
    const uint8_t payload[] = { 24, 150, 1, 1 };
    ICMPExtension ext(input, sizeof(input));
    EXPECT_EQ(1, ext.extension_class());
    EXPECT_EQ(1, ext.extension_type());
    EXPECT_EQ(
        ICMPExtension::payload_type(payload, payload + sizeof(payload)), 
        ext.payload()
    );

    ICMPExtension::serialization_type buffer = ext.serialize();
    EXPECT_EQ(
        ICMPExtension::serialization_type(input, input + sizeof(input)), 
        buffer
    );
}
