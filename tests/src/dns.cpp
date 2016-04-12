#include <gtest/gtest.h>
#include <iostream>
#include "dns.h"
#include "ipv6_address.h"
#include "utils.h"

using namespace Tins;


class DNSTest : public testing::Test {
public:
    static const uint8_t expected_packet[], dns_response1[],
                        dns_packet1[];
    
    void test_equals(const DNS& dns1, const DNS& dns2);
    void test_equals(const DNS::query& q1, const DNS::query& q2);
    void test_equals(const DNS::resource& q1, const DNS::resource& q2);
};

const uint8_t DNSTest::expected_packet[] = {
    0, 19, 215, 154, 0, 1, 0, 1, 0, 0, 0, 0, 3, 119, 119, 119, 7, 101, 
    120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1, 3, 119, 
    119, 119, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 
    0, 1, 0, 1, 0, 0, 18, 52, 0, 4, 192, 168, 0, 1
};

const uint8_t DNSTest::dns_response1[] = {
    174, 73, 129, 128, 0, 1, 0, 5, 0, 0, 0, 0, 6, 103, 111, 111, 103, 108, 
    101, 3, 99, 111, 109, 0, 0, 15, 0, 1, 192, 12, 0, 15, 0, 1, 0, 0, 2, 88, 
    0, 17, 0, 50, 4, 97, 108, 116, 52, 5, 97, 115, 112, 109, 120, 1, 108, 
    192, 12, 192, 12, 0, 15, 0, 1, 0, 0, 2, 88, 0, 9, 0, 40, 4, 97, 108, 
    116, 51, 192, 47, 192, 12, 0, 15, 0, 1, 0, 0, 2, 88, 0, 9, 0, 20, 4, 
    97, 108, 116, 49, 192, 47, 192, 12, 0, 15, 0, 1, 0, 0, 2, 88, 0, 4, 
    0, 10, 192, 47, 192, 12, 0, 15, 0, 1, 0, 0, 2, 88, 0, 9, 0, 30, 4, 97, 
    108, 116, 50, 192, 47
};

const uint8_t DNSTest::dns_packet1[] = {
    2, 225, 1, 32, 0, 1, 0, 0, 0, 0, 0, 0, 7, 118, 101, 114, 115, 105, 
    111, 110, 4, 98, 105, 110, 100, 192, 27, 0, 16, 0, 3
};



void DNSTest::test_equals(const DNS& dns1, const DNS& dns2) {
    EXPECT_EQ(dns1.id(), dns2.id());
    EXPECT_EQ(dns1.type(), dns2.type());
    EXPECT_EQ(dns1.opcode(), dns2.opcode());
    EXPECT_EQ(dns1.authoritative_answer(), dns2.authoritative_answer());
    EXPECT_EQ(dns1.truncated(), dns2.truncated());
    EXPECT_EQ(dns1.recursion_desired(), dns2.recursion_desired());
    EXPECT_EQ(dns1.recursion_available(), dns2.recursion_available());
    EXPECT_EQ(dns1.z(), dns2.z());
    EXPECT_EQ(dns1.authenticated_data(), dns2.authenticated_data());
    EXPECT_EQ(dns1.checking_disabled(), dns2.checking_disabled());
    EXPECT_EQ(dns1.rcode(), dns2.rcode());
    EXPECT_EQ(dns1.questions_count(), dns2.questions_count());
    EXPECT_EQ(dns1.answers_count(), dns2.answers_count());
    EXPECT_EQ(dns1.authority_count(), dns2.authority_count());
    EXPECT_EQ(dns1.additional_count(), dns2.additional_count());
    EXPECT_EQ(dns1.pdu_type(), dns2.pdu_type());
    EXPECT_EQ(dns1.header_size(), dns2.header_size());
    EXPECT_EQ(dns1.inner_pdu() != NULL, dns2.inner_pdu() != NULL);
}

void DNSTest::test_equals(const DNS::query& q1, const DNS::query& q2) {
    EXPECT_EQ(q1.dname(), q2.dname());
    EXPECT_EQ(q1.query_type(), q2.query_type());
    EXPECT_EQ(q1.query_class(), q2.query_class());
}

void DNSTest::test_equals(const DNS::resource& q1, const DNS::resource& q2) {
    EXPECT_EQ(q1.dname(), q2.dname());
    EXPECT_EQ(q1.data(), q2.data());
    EXPECT_EQ(q1.query_type(), q2.query_type());
    EXPECT_EQ(q1.query_class(), q2.query_class());
    EXPECT_EQ(q1.ttl(), q2.ttl());
}

TEST_F(DNSTest, ConstructorFromBuffer) {
    DNS dns(expected_packet, sizeof(expected_packet));
    // id=0x13, qr=1, opcode=0xa, aa=1, tc=1, rd=1, ra=1, z=0, rcode=0xa
    EXPECT_EQ(dns.id(), 0x13);
    EXPECT_EQ(dns.type(), DNS::RESPONSE);
    EXPECT_EQ(dns.opcode(), 0xa);
    EXPECT_EQ(dns.authoritative_answer(), 1);
    EXPECT_EQ(dns.truncated(), 1);
    EXPECT_EQ(dns.recursion_desired(), 1);
    EXPECT_EQ(dns.recursion_available(), 1);
    EXPECT_EQ(dns.z(), 0);
    EXPECT_EQ(dns.rcode(), 0xa);
    EXPECT_EQ(dns.questions_count(), 1);
    EXPECT_EQ(dns.answers_count(), 1);
    
    std::list<DNS::query> queries = dns.queries();
    ASSERT_EQ(queries.size(), 1U);
    test_equals(queries.front(), DNS::query("www.example.com", DNS::A, DNS::INTERNET));
    
    std::list<DNS::resource> answers = dns.answers();
    ASSERT_EQ(answers.size(), 1U);
    test_equals(answers.front(), DNS::resource("www.example.com", "192.168.0.1", DNS::A,
                                               DNS::INTERNET, 0x1234));
}

TEST_F(DNSTest, ConstructorFromBuffer2) {
    DNS dns(dns_response1, sizeof(dns_response1));
    EXPECT_EQ(dns.questions_count(), 1);
    EXPECT_EQ(dns.answers_count(), 5);
    
    for(size_t i = 0; i < 2; ++i) {   
        DNS::queries_type queries(dns.queries());
        for(DNS::queries_type::const_iterator it = queries.begin(); it != queries.end(); ++it) {
            EXPECT_EQ("google.com", it->dname());
            EXPECT_TRUE(it->query_type() == DNS::MX || it->query_type() == DNS::A);
            EXPECT_EQ(it->query_class(), DNS::INTERNET);
        }
         
        DNS::resources_type resources = dns.answers();
        size_t resource_index = 0;
        for(DNS::resources_type::const_iterator it = resources.begin(); it != resources.end(); ++it) {
            EXPECT_EQ("google.com", it->dname());
            EXPECT_EQ(DNS::MX, it->query_type());
            EXPECT_EQ(DNS::INTERNET, it->query_class());
            EXPECT_TRUE(
                it->data() == "alt1.aspmx.l.google.com" ||
                it->data() == "alt2.aspmx.l.google.com" ||
                it->data() == "alt3.aspmx.l.google.com" ||
                it->data() == "alt4.aspmx.l.google.com" ||
                it->data() == "alt5.aspmx.l.google.com" ||
                it->data() == "aspmx.l.google.com"
            );
            if (resource_index == 0) {
                EXPECT_EQ(50, it->preference());
            }
            else if (resource_index == 1) {
                EXPECT_EQ(40, it->preference());
            }
            resource_index++;
        }
        // Add some stuff and see if something gets broken
        if(i == 0) {
            dns.add_query(DNS::query("google.com", DNS::A, DNS::INTERNET));
            dns.add_query(DNS::query("google.com", DNS::MX, DNS::INTERNET));
            dns.add_answer(
                DNS::resource("google.com", "alt5.aspmx.l.google.com", DNS::MX,
                              DNS::INTERNET, 0x762)
            );
        }
    }
}

TEST_F(DNSTest, ConstructorFromBuffer3) {
    DNS dns(dns_packet1, sizeof(dns_packet1));
    EXPECT_EQ(dns.questions_count(), 1);
    DNS::queries_type queries = dns.queries();
    ASSERT_EQ(1UL, queries.size());
    EXPECT_EQ("version.bind", queries.front().dname());
}

TEST_F(DNSTest, NoRecords) {
    DNS dns;
    EXPECT_TRUE(dns.queries().empty());
    EXPECT_TRUE(dns.answers().empty());
    EXPECT_TRUE(dns.authority().empty());
    EXPECT_TRUE(dns.additional().empty());
}

TEST_F(DNSTest, Serialization) {
    DNS dns(expected_packet, sizeof(expected_packet));
    DNS::serialization_type buffer = dns.serialize();
    ASSERT_EQ(buffer.size(), sizeof(expected_packet));
    EXPECT_TRUE(std::equal(buffer.begin(), buffer.end(), expected_packet));
}

TEST_F(DNSTest, CopyConstructor) {
    DNS dns1(expected_packet, sizeof(expected_packet));
    DNS dns2(dns1);
    test_equals(dns1, dns2);
}

TEST_F(DNSTest, CopyAssignmentOperator) {
    DNS dns1(expected_packet, sizeof(expected_packet));
    DNS dns2;
    dns2 = dns1;
    test_equals(dns1, dns2);
}

TEST_F(DNSTest, NestedCopy) {
    DNS* nested = new DNS(expected_packet, sizeof(expected_packet));
    DNS dns1(expected_packet, sizeof(expected_packet));
    dns1.inner_pdu(nested);
    DNS dns2(dns1);
    test_equals(dns1, dns2);
    dns2.inner_pdu(0);
    dns2 = dns1;
    test_equals(dns1, dns2);
}

TEST_F(DNSTest, ID) {
    DNS dns;
    dns.id(0x7263);
    EXPECT_EQ(dns.id(), 0x7263);
}

TEST_F(DNSTest, Type) {
    DNS dns;
    dns.type(DNS::RESPONSE);
    EXPECT_EQ(dns.type(), DNS::RESPONSE);
}

TEST_F(DNSTest, Opcode) {
    DNS dns;
    dns.opcode(0xa);
    EXPECT_EQ(dns.opcode(), 0xa);
}

TEST_F(DNSTest, AuthoritativeAnswer) {
    DNS dns;
    dns.authoritative_answer(1);
    EXPECT_EQ(dns.authoritative_answer(), 1);
}

TEST_F(DNSTest, Truncated) {
    DNS dns;
    dns.truncated(1);
    EXPECT_EQ(dns.truncated(), 1);
}

TEST_F(DNSTest, RecursionDesired) {
    DNS dns;
    dns.recursion_desired(1);
    EXPECT_EQ(dns.recursion_desired(), 1);
}

TEST_F(DNSTest, RecursionAvailable) {
    DNS dns;
    dns.recursion_available(1);
    EXPECT_EQ(dns.recursion_available(), 1);
}

TEST_F(DNSTest, Z) {
    DNS dns;
    dns.z(1);
    EXPECT_EQ(dns.z(), 1);
}

TEST_F(DNSTest, AuthenticatedData) {
    DNS dns;
    dns.authenticated_data(1);
    EXPECT_EQ(dns.authenticated_data(), 1);
}

TEST_F(DNSTest, CheckingDisabled) {
    DNS dns;
    dns.checking_disabled(1);
    EXPECT_EQ(dns.checking_disabled(), 1);
}

TEST_F(DNSTest, RCode) {
    DNS dns;
    dns.rcode(0xa);
    EXPECT_EQ(dns.rcode(), 0xa);
}

TEST_F(DNSTest, Question) {
    DNS dns;
    dns.add_query(DNS::query("www.example.com", DNS::A, DNS::INTERNET));
    dns.add_query(DNS::query("www.example2.com", DNS::MX, DNS::INTERNET));
    ASSERT_EQ(dns.questions_count(), 2);
    
    DNS::queries_type queries(dns.queries());
    for(DNS::queries_type::const_iterator it = queries.begin(); it != queries.end(); ++it) {
        EXPECT_TRUE(it->dname() == "www.example.com" || it->dname() == "www.example2.com");
        if(it->dname() == "www.example.com") {
            EXPECT_EQ(it->query_type(), DNS::A);
            EXPECT_EQ(it->query_class(), DNS::INTERNET);
        }
        else if(it->dname() == "www.example2.com") {
            EXPECT_EQ(it->query_type(), DNS::MX);
            EXPECT_EQ(it->query_class(), DNS::INTERNET);
        }
    }
}

TEST_F(DNSTest, Answers) {
    DNS dns;
    dns.add_answer(
        DNS::resource("www.example.com", "127.0.0.1", DNS::A, DNS::INTERNET, 0x762)
    );
    dns.add_answer(
        DNS::resource("www.example2.com", "mail.example.com", DNS::MX, DNS::INTERNET, 0x762)
    );
    
    ASSERT_EQ(dns.answers_count(), 2);
    
    DNS::resources_type resources = dns.answers();
    for(DNS::resources_type::const_iterator it = resources.begin(); it != resources.end(); ++it) {
        EXPECT_TRUE(it->dname() == "www.example.com" || it->dname() == "www.example2.com");
        if(it->dname() == "www.example.com") {
            EXPECT_EQ(it->query_type(), DNS::A);
            EXPECT_EQ(it->ttl(), 0x762U);
            EXPECT_EQ(it->data(), "127.0.0.1");
            EXPECT_EQ(it->query_class(), DNS::INTERNET);
        }
        else if(it->dname() == "www.example2.com") {
            EXPECT_EQ(it->query_type(), DNS::MX);
            EXPECT_EQ(it->ttl(), 0x762U);
            EXPECT_EQ(it->data(), "mail.example.com");
            EXPECT_EQ(it->query_class(), DNS::INTERNET);
        }
    }
}

TEST_F(DNSTest, Authority) {
    DNS dns;
    
    const char* domain = "carlos.example.com";
    dns.add_authority(
        DNS::resource("www.example.com", domain, DNS::CNAME, DNS::INTERNET, 0x762)
    );
    dns.add_authority(
        DNS::resource("www.example.com", domain, DNS::CNAME, DNS::INTERNET, 0x762)
    );
    
    ASSERT_EQ(dns.authority_count(), 2);
    
    DNS::resources_type resources = dns.authority();
    EXPECT_EQ(2ULL, resources.size());
    for(DNS::resources_type::const_iterator it = resources.begin(); it != resources.end(); ++it) {
        EXPECT_EQ("www.example.com", it->dname());
        EXPECT_EQ(it->query_type(), DNS::CNAME);
        EXPECT_EQ(it->ttl(), 0x762U);
        EXPECT_EQ(it->data(), domain);
        EXPECT_EQ(it->query_class(), DNS::INTERNET);
    }
}

TEST_F(DNSTest, Additional) {
    DNS dns;
    
    const char* domain = "carlos.example.com";
    dns.add_additional(
        DNS::resource("www.example.com", domain, DNS::CNAME, DNS::INTERNET, 0x762)
    );
    dns.add_additional(
        DNS::resource("www.example.com", domain, DNS::CNAME, DNS::INTERNET, 0x762)
    );
    
    ASSERT_EQ(dns.additional_count(), 2);
    
    DNS::resources_type resources = dns.additional();
    for(DNS::resources_type::const_iterator it = resources.begin(); it != resources.end(); ++it) {
        EXPECT_EQ("www.example.com", it->dname());
        EXPECT_EQ(it->ttl(), 0x762U);
        EXPECT_EQ(it->data(), domain);
        EXPECT_EQ(it->query_type(), DNS::CNAME);
        EXPECT_EQ(it->query_class(), DNS::INTERNET);
    }
}

TEST_F(DNSTest, AnswersWithSameName) {
    DNS dns;
    dns.add_answer(
        DNS::resource("www.example.com", "127.0.0.1", DNS::A, DNS::INTERNET, 0x762)
    );
    dns.add_answer(
        DNS::resource("www.example.com", "127.0.0.2", DNS::A, DNS::INTERNET, 0x762)
    );
    ASSERT_EQ(dns.answers_count(), 2);
    DNS::resources_type resources = dns.answers();
    for(DNS::resources_type::const_iterator it = resources.begin(); it != resources.end(); ++it) {
        EXPECT_TRUE(it->data() == "127.0.0.1" || it->data() == "127.0.0.2");
        EXPECT_EQ(it->dname(), "www.example.com");
        EXPECT_EQ(it->ttl(), 0x762U);
        EXPECT_EQ(it->query_type(), DNS::A);
        EXPECT_EQ(it->query_class(), DNS::INTERNET);
    }
}

TEST_F(DNSTest, AnswersV6) {
    DNS dns;
    dns.add_answer(
        DNS::resource("www.example.com", "f9a8:239::1:1", DNS::AAAA, DNS::INTERNET, 0x762)
    );
    dns.add_answer(
        DNS::resource("www.example.com", "f9a8:239::1:1", DNS::AAAA, DNS::INTERNET, 0x762)
    );
    ASSERT_EQ(dns.answers_count(), 2);
    
    DNS::resources_type resources = dns.answers();
    for(DNS::resources_type::const_iterator it = resources.begin(); it != resources.end(); ++it) {
        EXPECT_EQ(it->dname(), "www.example.com");
        EXPECT_EQ(it->ttl(), 0x762U);
        EXPECT_EQ(it->data(), "f9a8:239::1:1");
        EXPECT_EQ(it->query_type(), DNS::AAAA);
        EXPECT_EQ(it->query_class(), DNS::INTERNET);
    }
}

TEST_F(DNSTest, ItAintGonnaCorrupt) {
    DNS dns(dns_response1, sizeof(dns_response1));
    EXPECT_EQ(dns.questions_count(), 1);
    EXPECT_EQ(dns.answers_count(), 5);

    const char* domain = "carlos.example.com";
    dns.add_additional(
        DNS::resource("www.example.com", domain, DNS::CNAME, DNS::INTERNET, 0x762)
    );
    dns.add_authority(
        DNS::resource("www.example.com", domain, DNS::CNAME, DNS::INTERNET, 0x762)
    );
    dns.add_query(DNS::query("google.com", DNS::A, DNS::INTERNET));

    DNS::queries_type queries(dns.queries());
    for(DNS::queries_type::const_iterator it = queries.begin(); it != queries.end(); ++it) {
        EXPECT_EQ("google.com", it->dname());
        EXPECT_TRUE(it->query_type() == DNS::MX || it->query_type() == DNS::A);
        EXPECT_EQ(it->query_class(), DNS::INTERNET);
    }
    
    // Check answers
    DNS::resources_type resources = dns.answers();
    for(DNS::resources_type::const_iterator it = resources.begin(); it != resources.end(); ++it) {
        EXPECT_EQ("google.com", it->dname());
        EXPECT_EQ(DNS::MX, it->query_type());
        EXPECT_EQ(DNS::INTERNET, it->query_class());
        EXPECT_TRUE(
            it->data() == "alt1.aspmx.l.google.com" ||
            it->data() == "alt2.aspmx.l.google.com" ||
            it->data() == "alt3.aspmx.l.google.com" ||
            it->data() == "alt4.aspmx.l.google.com" ||
            it->data() == "alt5.aspmx.l.google.com" ||
            it->data() == "aspmx.l.google.com"
        );
    }
    
    // Check authority records
    resources = dns.authority();
    EXPECT_EQ(1ULL, resources.size());
    for(DNS::resources_type::const_iterator it = resources.begin(); it != resources.end(); ++it) {
        EXPECT_EQ("www.example.com", it->dname());
        EXPECT_EQ(it->query_type(), DNS::CNAME);
        EXPECT_EQ(it->ttl(), 0x762U);
        EXPECT_EQ(it->data(), domain);
        EXPECT_EQ(it->query_class(), DNS::INTERNET);
    }
    
        
    // Check additional records
    resources = dns.additional();
    EXPECT_EQ(1ULL, resources.size());
    for(DNS::resources_type::const_iterator it = resources.begin(); it != resources.end(); ++it) {
        EXPECT_EQ("www.example.com", it->dname());
        EXPECT_EQ(it->query_type(), DNS::CNAME);
        EXPECT_EQ(it->ttl(), 0x762U);
        EXPECT_EQ(it->data(), domain);
        EXPECT_EQ(it->query_class(), DNS::INTERNET);
    }
}

TEST_F(DNSTest, MXPreferenceField) {
    DNS dns1;
    dns1.add_answer(
        DNS::resource("example.com", "mail.example.com", DNS::MX, DNS::INTERNET, 0x762, 42)
    );
    DNS::serialization_type buffer = dns1.serialize();
    DNS dns2(&buffer[0], buffer.size());
    DNS::resources_type answers = dns1.answers();
    ASSERT_EQ(1UL, answers.size());

    const DNS::resource& resource = *answers.begin();
    EXPECT_EQ(42, resource.preference());
    EXPECT_EQ("example.com", resource.dname());
}

TEST_F(DNSTest, SOARecordConstructor) {
    DNS::soa_record r(
        "hehehehe.example.com", 
        "john.example.com",
        0x9823ade9,
        0x918273aa,
        0x827361ad,
        0x8ad71928,
        0x1ad92871
    );
    EXPECT_EQ("hehehehe.example.com", r.mname());
    EXPECT_EQ("john.example.com", r.rname());
    EXPECT_EQ(0x9823ade9, r.serial());
    EXPECT_EQ(0x918273aa, r.refresh());
    EXPECT_EQ(0x827361ad, r.retry());
    EXPECT_EQ(0x8ad71928, r.expire());
    EXPECT_EQ(0x1ad92871U, r.minimum_ttl());
}

TEST_F(DNSTest, SOARecordGettersAndSetters) {
    DNS::soa_record r;
    r.mname("hehehehe.example.com");
    r.rname("john.example.com");
    r.serial(0x9823ade9);
    r.refresh(0x918273aa);
    r.retry(0x827361ad);
    r.expire(0x8ad71928);
    r.minimum_ttl(0x1ad92871);
    EXPECT_EQ("hehehehe.example.com", r.mname());
    EXPECT_EQ("john.example.com", r.rname());
    EXPECT_EQ(0x9823ade9, r.serial());
    EXPECT_EQ(0x918273aa, r.refresh());
    EXPECT_EQ(0x827361ad, r.retry());
    EXPECT_EQ(0x8ad71928, r.expire());
    EXPECT_EQ(0x1ad92871U, r.minimum_ttl());
}

TEST_F(DNSTest, SOARecordFromBuffer) {
    const uint8_t raw[] = {
        232, 101, 129, 128, 0, 1, 0, 1, 0, 0, 0, 0, 6, 103, 111, 111, 103, 108,
        101, 3, 99, 111, 109, 0, 0, 6, 0, 1, 192, 12, 0, 6, 0, 1, 0, 0, 0, 59, 
        0, 38, 3, 110, 115, 50, 192, 12, 9, 100, 110, 115, 45, 97, 100, 109, 105,
        110, 192, 12, 6, 174, 163, 84, 0, 0, 3, 132, 0, 0, 3, 132, 0, 0, 7, 8, 0,
        0, 0, 60
    };

    DNS dns(raw, sizeof(raw));
    ASSERT_EQ(1UL, dns.answers().size());
    DNS::resource r(dns.answers().front());
    DNS::soa_record soa(r);
    EXPECT_EQ("ns2.google.com", soa.mname());
    EXPECT_EQ("dns-admin.google.com", soa.rname());
    EXPECT_EQ(112108372U, soa.serial());
    EXPECT_EQ(900U, soa.refresh());
    EXPECT_EQ(900U, soa.retry());
    EXPECT_EQ(1800U, soa.expire());
    EXPECT_EQ(60U, soa.minimum_ttl());
}

TEST_F(DNSTest, SOARecordSerialize) {
    DNS::soa_record r1;
    r1.mname("hehehehe.example.com");
    r1.rname("john.example.com");
    r1.serial(0x9823ade9);
    r1.refresh(0x918273aa);
    r1.retry(0x827361ad);
    r1.expire(0x8ad71928);
    r1.minimum_ttl(0x1ad92871);

    DNS::serialization_type buffer = r1.serialize();
    DNS::soa_record r2(&buffer[0], buffer.size());
    EXPECT_EQ("hehehehe.example.com", r2.mname());
    EXPECT_EQ("john.example.com", r2.rname());
    EXPECT_EQ(0x9823ade9U, r2.serial());
    EXPECT_EQ(0x918273aaU, r2.refresh());
    EXPECT_EQ(0x827361adU, r2.retry());
    EXPECT_EQ(0x8ad71928U, r2.expire());
    EXPECT_EQ(0x1ad92871U, r2.minimum_ttl());
}
