#include <gtest/gtest.h>
#include "icmp_extension.h"
#include "mpls.h"

using Tins::ICMPExtension;
using Tins::ICMPExtensionsStructure;
using Tins::MPLS;
using Tins::PDU;

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

TEST_F(ICMPExtensionTest, ExtensionClass) {
    ICMPExtension extension;
    extension.extension_class(126);
    EXPECT_EQ(126, extension.extension_class());
}

TEST_F(ICMPExtensionTest, ExtensionType) {
    ICMPExtension extension;
    extension.extension_type(126);
    EXPECT_EQ(126, extension.extension_type());
}

TEST_F(ICMPExtensionTest, Payload) {
    ICMPExtension::payload_type payload;
    payload.push_back(0x92);
    payload.push_back(0x1a);
    payload.push_back(0xde);
    ICMPExtension extension;
    extension.payload(payload);
    EXPECT_EQ(payload, extension.payload());
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
    EXPECT_EQ(1UL, extensions.size());
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

TEST_F(ICMPExtensionTest, Version) {
    ICMPExtensionsStructure structure;
    structure.reserved(0xdea);
    structure.version(0xf);
    EXPECT_EQ(0xdea, structure.reserved());
    EXPECT_EQ(0xf, structure.version());
}

TEST_F(ICMPExtensionTest, MPLSExtension) {
    ICMPExtensionsStructure structure;
    MPLS mpls1;
    mpls1.label(10012);
    mpls1.bottom_of_stack(1);
    mpls1.ttl(15);
    structure.add_extension(mpls1);
    
    PDU::serialization_type buffer = structure.serialize();
    ICMPExtensionsStructure new_structure(&buffer[0], buffer.size());
    ASSERT_EQ(1UL, new_structure.extensions().size());
    MPLS mpls2(*new_structure.extensions().begin());
    EXPECT_EQ(mpls1.label(), mpls2.label());
    EXPECT_EQ(mpls1.bottom_of_stack(), mpls2.bottom_of_stack());
    EXPECT_EQ(mpls1.ttl(), mpls2.ttl());
}
