#include <gtest/gtest.h>
#include "icmp_extension.h"

using Tins::ICMPExtension;
using Tins::ICMPExtensionsStructure;

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

TEST_F(ICMPExtensionTest, ExtensionStructureValidation) {
    const uint8_t input[] = { 32, 0, 197, 95, 0, 8, 1, 1, 24, 150, 1, 1 };
    EXPECT_TRUE(ICMPExtensionsStructure::validate_extensions(input, sizeof(input)));
}

TEST_F(ICMPExtensionTest, ExtensionStructureFromBuffer) {
    const uint8_t input[] = { 32, 0, 197, 95, 0, 8, 1, 1, 24, 150, 1, 1 };
    ICMPExtensionsStructure structure(input, sizeof(input));
    EXPECT_EQ(2, structure.version());
    EXPECT_EQ(0, structure.reserved());
    EXPECT_EQ(0xc55f, structure.checksum());
    const ICMPExtensionsStructure::extensions_type& extensions = structure.extensions();
    EXPECT_EQ(1, extensions.size());
    const ICMPExtension& ext = *extensions.begin();

    const uint8_t payload[] = { 24, 150, 1, 1 };
    EXPECT_EQ(1, ext.extension_class());
    EXPECT_EQ(1, ext.extension_type());
    EXPECT_EQ(
        ICMPExtension::payload_type(payload, payload + sizeof(payload)), 
        ext.payload()
    );

    ICMPExtension::serialization_type buffer = structure.serialize();
    EXPECT_EQ(
        ICMPExtension::serialization_type(input, input + sizeof(input)), 
        buffer
    );
}

TEST_F(ICMPExtensionTest, Reserved) {
    ICMPExtensionsStructure structure;
    structure.reserved(0xdea);
    EXPECT_EQ(0xdea, structure.reserved());
    EXPECT_EQ(2, structure.version());
}
