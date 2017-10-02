#include <algorithm>
#include <map>
#include <gtest/gtest.h>
#include <tins/ip.h>
#include <tins/tcp.h>
#include <tins/rawpdu.h>
#include <tins/pdu_iterator.h>

using std::distance;
using std::map;

using namespace Tins;

class PDUIteratorTest : public testing::Test {
public:
    template <typename Iterator>
    void test() {
        IP ip = IP("1.2.3.4", "4.3.2.1") / TCP(22, 23) / RawPDU("asd");
        map<int, PDU::PDUType> pdu_types;
        pdu_types[0] = PDU::IP;
        pdu_types[1] = PDU::TCP;
        pdu_types[2] = PDU::RAW;

        PDUIteratorRange<Iterator> range = iterate_pdus(ip);
        EXPECT_EQ(3, distance(range.begin(), range.end()));

        size_t iteration = 0;
        for (Iterator iter = range.begin(); iter != range.end(); iter++) {
            EXPECT_EQ(pdu_types[iteration], iter->pdu_type());
            EXPECT_EQ(pdu_types[iteration], (*iter).pdu_type());
            ++iteration;
        }

        Iterator iter = range.begin();
        ++iter;
        iter++;
        --iter;
        iter--;
        EXPECT_EQ(PDU::IP, iter->pdu_type());
        EXPECT_EQ(iter, range.begin());
        EXPECT_NE(iter, range.end());

        const PDU& pdu = *iterate_pdus(ip).begin();
        EXPECT_EQ(PDU::IP, pdu.pdu_type());
        EXPECT_GT(const_cast<PDU&>(pdu).serialize().size(), 0UL);
    }
};

TEST_F(PDUIteratorTest, Range) {
    test<PDUIterator>();
}

TEST_F(PDUIteratorTest, RangeConst) {
    test<ConstPDUIterator>();
}
