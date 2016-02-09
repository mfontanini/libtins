#include "cxxstd.h"

#if TINS_IS_CXX11

#include <gtest/gtest.h>
#include <iostream>
#include <algorithm>
#include <string>
#include <limits>
#include <cassert>
#include "tcp_ip.h"
#include "tcp.h"
#include "ip.h"
#include "ip_address.h"
#include "ipv6_address.h"
#include "exceptions.h"
#include "ethernetII.h"
#include "rawpdu.h"
#include "utils.h"

using namespace std;
using namespace Tins;
using namespace Tins::TCPIP;

class FlowTest : public testing::Test {
public:
    struct order_element {
        order_element(size_t payload_index, uint32_t payload_size) 
        : payload_index(payload_index),payload_size(payload_size) {

        }

        size_t payload_index;
        uint32_t payload_size;
    };

    static const size_t num_packets = 20;
    static EthernetII packets[], overlapped_packets1[], 
                      overlapped_packets2[], overlapped_packets3[],
                      overlapped_packets4[], overlapped_packets5[];
    static const string payload;
    typedef vector<order_element> ordering_info_type;
    
    void cumulative_flow_data_handler(Flow& flow);
    void on_new_stream(Stream& stream);
    void cumulative_stream_client_data_handler(Stream& stream);
    void cumulative_stream_server_data_handler(Stream& stream);
    void buffered_payload_handle(Flow& session);
    void run_test(uint32_t initial_seq, const ordering_info_type& chunks, 
                  const string& payload);
    void run_test(uint32_t initial_seq, const ordering_info_type& chunks);
    void run_tests(const ordering_info_type& chunks, const string& payload);
    void run_tests(const ordering_info_type& chunks);
    ordering_info_type split_payload(const string& payload, uint32_t chunk_size);
    string merge_chunks(const vector<Flow::payload_type>& chunks);
    vector<EthernetII> chunks_to_packets(uint32_t initial_seq,
                                         const ordering_info_type& chunks, 
                                         const string& payload);
    vector<EthernetII> three_way_handshake(uint32_t client_seq, uint32_t server_seq,
                                           IPv4Address client_addr, uint16_t client_port,
                                           IPv4Address server_addr, uint16_t server_port);
    void set_endpoints(vector<EthernetII>& packets, IPv4Address src_addr,
                       uint16_t src_port, IPv4Address dst_addr,
                       uint16_t dst_port);
    
    vector<Flow::payload_type> flow_payload_chunks;
    vector<Flow::payload_type> stream_client_payload_chunks;
    vector<Flow::payload_type> stream_server_payload_chunks;
};

const string FlowTest::payload = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
                                 "Sed at aliquam arcu. Sed at iaculis magna. Nam ut dolor "
                                 "eget velit mattis posuere ut non dui. Aliquam faucibus "
                                 "erat pretium ligula tincidunt eget tristique justo placerat. "
                                 "Phasellus turpis tellus, ornare ultricies egestas vitae, "
                                 "mollis sed neque. Sed et libero in nunc pharetra auctor ut "
                                 "a eros. Mauris quis faucibus nibh. \nLorem ipsum dolor sit "
                                 "amet, consectetur adipiscing elit. Sed at aliquam arcu. "
                                 "Sed at iaculis magna. Nam ut dolor eget velit mattis "
                                 "posuere ut non dui. Aliquam faucibus erat pretium ligula "
                                 "tincidunt eget tristique justo placerat. Phasellus turpis "
                                 "tellus, ornare ultricies egestas vitae, mollis sed neque. "
                                 "Sed et libero in nunc pharetra auctor ut a eros. Mauris "
                                 "quis faucibus nibh. \n\n\nCurabitur sem erat, bibendum "
                                 "quis condimentum ut, imperdiet at est. Duis sagittis rhoncus "
                                 "felis at ultricies. In libero urna, dignissim eu elementum "
                                 "quis, consectetur a neque. Praesent leo sem, cursus sed lobortis "
                                 "sit amet, ornare ac augue. Mauris tristique semper ipsum at "
                                 "consequat. Sed fringilla dolor ut lacus sagittis quis ultricies "
                                 "leo vulputate. Maecenas dignissim imperdiet justo. Cras libero "
                                 "odio, vehicula et adipiscing quis, luctus vel ante. \nAliquam "
                                 "imperdiet est quis nunc malesuada eget convallis tellus "
                                 "ullamcorper. Vivamus ullamcorper eros sit amet odio sollicitudin "
                                 "rutrum. Donec pellentesque faucibus nulla, ut fringilla risus "
                                 "aliquam eget. Sed et ante mi. Morbi a turpis et tellus dapibus "
                                 "iaculis. Etiam faucibus tellus sed metus consequat rutrum. "
                                 "Fusce sit amet nulla massa, tempus vulputate sem. Cras tincidunt "
                                 "quam in libero rutrum interdum. Aliquam quam sapien, facilisis "
                                 "at vestibulum et, venenatis id mauris. Morbi rutrum gravida "
                                 "ultricies. \nAenean et justo ut libero euismod sollicitudin. "
                                 "Nullam enim dui, iaculis vitae bibendum et, commodo in tellus. "
                                 "Nullam eget purus mi, a ullamcorper lorem. Suspendisse potenti. "
                                 "Duis ac justo ut leo euismod gravida sit amet at lectus. Lorem "
                                 "ipsum dolor sit amet, consectetur adipiscing elit. Maecenas sed "
                                 "arcu vitae nisi sollicitudin gravida. Nulla facilisis nibh turpis. "
                                 "Maecenas quis imperdiet arcu. Sed sit amet nulla urna, at "
                                 "vestibulum mauris. Suspendisse quis elit dui. Class aptent taciti "
                                 "sociosqu ad litora torquent per conubia nostra, per inceptos "
                                 "himenaeos. \n";

void FlowTest::cumulative_flow_data_handler(Flow& flow) {
    flow_payload_chunks.push_back(flow.payload());
    flow.payload().clear();
}

void FlowTest::on_new_stream(Stream& stream) {
    using std::placeholders::_1;
    stream.client_data_callback(bind(&FlowTest::cumulative_stream_client_data_handler,
                                     this, _1));
}

void FlowTest::cumulative_stream_client_data_handler(Stream& stream) {
    stream_client_payload_chunks.push_back(stream.client_flow().payload());
}

void FlowTest::cumulative_stream_server_data_handler(Stream& stream) {
    stream_server_payload_chunks.push_back(stream.server_flow().payload());
}

void FlowTest::buffered_payload_handle(Flow& session) {

}

void FlowTest::run_test(uint32_t initial_seq, const ordering_info_type& chunks, 
                        const string& payload) {
    using std::placeholders::_1;
    flow_payload_chunks.clear();

    Flow flow(IPv4Address("1.2.3.4"), 22, initial_seq);
    flow.data_callback(bind(&FlowTest::cumulative_flow_data_handler, this, _1));
    vector<EthernetII> packets = chunks_to_packets(initial_seq, chunks, payload);
    for (size_t i = 0; i < packets.size(); ++i) {
        flow.process_packet(packets[i]);
    }
    string flow_payload = merge_chunks(flow_payload_chunks);
    EXPECT_EQ(payload, string(flow_payload.begin(), flow_payload.end()));
}

void FlowTest::run_test(uint32_t initial_seq, const ordering_info_type& chunks) {
    run_test(initial_seq, chunks, payload);
}

void FlowTest::run_tests(const ordering_info_type& chunks, const string& payload) {
    run_test(0, chunks, payload);
    run_test(20, chunks, payload);
    run_test(numeric_limits<uint32_t>::max() / 2, chunks, payload);
    run_test(numeric_limits<uint32_t>::max() - 2, chunks, payload);
    run_test(numeric_limits<uint32_t>::max() - 5, chunks, payload);
    run_test(numeric_limits<uint32_t>::max() - 10, chunks, payload);
    run_test(numeric_limits<uint32_t>::max() - 34, chunks, payload);
    run_test(numeric_limits<uint32_t>::max() - 31, chunks, payload);
}

void FlowTest::run_tests(const ordering_info_type& chunks) {
    run_tests(chunks, payload);
}

FlowTest::ordering_info_type FlowTest::split_payload(const string& payload,
                                                     uint32_t chunk_size) {
    ordering_info_type output;
    uint32_t chunk_count = payload.size() / chunk_size;
    for (uint32_t i = 0; i < chunk_count; ++i) {
        output.push_back(order_element(i * chunk_size, chunk_size));
    }
    if (chunk_count * chunk_size < payload.size()) {
        uint32_t index = chunk_count * chunk_size;
        output.push_back(order_element(index, payload.size() - index));
    }
    return output;
}

string FlowTest::merge_chunks(const vector<Flow::payload_type>& chunks) {
    string output;
    for (size_t i = 0; i < chunks.size(); ++i) {
        Flow::payload_type this_chunk = chunks[i];
        output += string(this_chunk.begin(), this_chunk.end());
    }
    return output;
}

vector<EthernetII> FlowTest::chunks_to_packets(uint32_t initial_seq,
                                               const ordering_info_type& chunks, 
                                               const string& payload) {
    vector<EthernetII> output;
    for (size_t i = 0; i < chunks.size(); ++i) {
        const order_element& element = chunks[i];
        assert(element.payload_index + element.payload_size <= payload.size());
        TCP tcp;
        RawPDU raw(payload.begin() + element.payload_index, 
                   payload.begin() + element.payload_index + element.payload_size);
        tcp.seq(initial_seq + element.payload_index);
        output.push_back(EthernetII() / IP() / tcp / raw);
    }
    return output;
}

vector<EthernetII> FlowTest::three_way_handshake(uint32_t client_seq, uint32_t server_seq,
                                                 IPv4Address client_addr, uint16_t client_port,
                                                 IPv4Address server_addr, uint16_t server_port) {
    vector<EthernetII> output;
    output.push_back(EthernetII() / IP(server_addr, client_addr) / TCP(server_port, client_port));
    output.push_back(EthernetII() / IP(client_addr, server_addr) / TCP(client_port, server_port));
    output.push_back(EthernetII() / IP(server_addr, client_addr) / TCP(server_port, client_port));
    output[0].rfind_pdu<TCP>().flags(TCP::SYN);
    output[0].rfind_pdu<TCP>().seq(client_seq);
    output[1].rfind_pdu<TCP>().flags(TCP::SYN | TCP::ACK);
    output[1].rfind_pdu<TCP>().seq(server_seq);
    output[1].rfind_pdu<TCP>().ack_seq(client_seq + 1);
    output[2].rfind_pdu<TCP>().flags(TCP::ACK);
    output[2].rfind_pdu<TCP>().seq(client_seq + 1);
    output[2].rfind_pdu<TCP>().ack_seq(server_seq + 1);
    return output;
}

void FlowTest::set_endpoints(vector<EthernetII>& packets, IPv4Address src_addr,
                             uint16_t src_port, IPv4Address dst_addr,
                             uint16_t dst_port) {
    for (size_t i = 0; i < packets.size(); ++i) {
        packets[i].rfind_pdu<IP>().src_addr(src_addr);
        packets[i].rfind_pdu<IP>().dst_addr(dst_addr);
        packets[i].rfind_pdu<TCP>().sport(src_port);
        packets[i].rfind_pdu<TCP>().dport(dst_port);
    }
}

TEST_F(FlowTest, ReassembleStreamPlain) {
    ordering_info_type chunks = split_payload(payload, 5);
    run_tests(chunks);
}

TEST_F(FlowTest, ReassembleStreamReordering) {
    ordering_info_type chunks = split_payload(payload, 5);
    // e.g. input [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    // after this it's [2, 1, 0, 3, 6, 5, 4, 7, 10, 9, 8]
    for (size_t i = 0; i < chunks.size(); i += 4) {
        if (i + 2 < chunks.size()) {
            swap(chunks[i], chunks[i + 2]);
        }
    }
    run_tests(chunks);
}

TEST_F(FlowTest, ReassembleStreamReversed) {
    ordering_info_type chunks = split_payload(payload, 5);
    reverse(chunks.begin(), chunks.end());
    run_tests(chunks);
}

TEST_F(FlowTest, Overlapping) {
    string payload = "Hello world. This is a payload";
    ordering_info_type chunks;
    // "Hello "
    chunks.push_back(order_element(0, 6));
    // "ello Wo"
    chunks.push_back(order_element(1, 7));
    // "lo World"
    chunks.push_back(order_element(3, 8));
    chunks.push_back(order_element(10, payload.size() - 10));
    chunks.push_back(order_element(9, 1));
    run_tests(chunks, payload);

    reverse(chunks.begin(), chunks.end());
    run_tests(chunks, payload);

    swap(chunks[2], chunks[4]);
    run_tests(chunks, payload);
}

TEST_F(FlowTest, IgnoreDataPackets) {
    using std::placeholders::_1;

    ordering_info_type chunks = split_payload(payload, 5);
    Flow flow(IPv4Address("1.2.3.4"), 22, 0);
    flow.data_callback(bind(&FlowTest::cumulative_flow_data_handler, this, _1));
    flow.ignore_data_packets();
    vector<EthernetII> packets = chunks_to_packets(0, chunks, payload);
    for (size_t i = 0; i < packets.size(); ++i) {
        flow.process_packet(packets[i]);
    }
    EXPECT_TRUE(flow_payload_chunks.empty());
}

// Stream follower tests

TEST_F(FlowTest, StreamFollower_ThreeWayHandshake) {
    using std::placeholders::_1;

    vector<EthernetII> packets = three_way_handshake(29, 60, "1.2.3.4", 22, "4.3.2.1", 25);
    packets[0].src_addr("00:01:02:03:04:05");
    packets[0].dst_addr("05:04:03:02:01:00");
    StreamFollower follower;
    follower.new_stream_callback(bind(&FlowTest::on_new_stream, this, _1));
    for (size_t i = 0; i < packets.size(); ++i) {
        follower.process_packet(packets[i]);
    }
    Stream& stream = follower.find_stream(IPv4Address("1.2.3.4"), 22,
                                          IPv4Address("4.3.2.1"), 25);
    EXPECT_EQ(Flow::ESTABLISHED, stream.client_flow().state());
    EXPECT_EQ(Flow::SYN_SENT, stream.server_flow().state());
    EXPECT_EQ(30, stream.client_flow().sequence_number());
    EXPECT_EQ(60, stream.server_flow().sequence_number());
    EXPECT_EQ(IPv4Address("4.3.2.1"), stream.client_flow().dst_addr_v4());
    EXPECT_EQ(25, stream.client_flow().dport());
    EXPECT_EQ(IPv4Address("1.2.3.4"), stream.server_flow().dst_addr_v4());
    EXPECT_EQ(22, stream.server_flow().dport());
    EXPECT_EQ(IPv4Address("1.2.3.4"), stream.client_addr_v4());
    EXPECT_EQ(IPv4Address("4.3.2.1"), stream.server_addr_v4());
    EXPECT_EQ(HWAddress<6>("00:01:02:03:04:05"), stream.client_hw_addr());
    EXPECT_EQ(HWAddress<6>("05:04:03:02:01:00"), stream.server_hw_addr());
    EXPECT_EQ(22, stream.client_port());
    EXPECT_EQ(25, stream.server_port());

    IP server_packet = IP("1.2.3.4", "4.3.2.1") / TCP(22, 25);
    server_packet.rfind_pdu<TCP>().flags(TCP::ACK);
    follower.process_packet(server_packet);

    EXPECT_EQ(Flow::ESTABLISHED, stream.server_flow().state());
    EXPECT_EQ(61, stream.server_flow().sequence_number());
}

TEST_F(FlowTest, StreamFollower_RSTClosesStream) {
    using std::placeholders::_1;

    vector<EthernetII> packets = three_way_handshake(29, 60, "1.2.3.4", 22, "4.3.2.1", 25);
    StreamFollower follower;
    follower.new_stream_callback(bind(&FlowTest::on_new_stream, this, _1));
    for (size_t i = 0; i < packets.size(); ++i) {
        follower.process_packet(packets[i]);
    }
    Stream stream = follower.find_stream(IPv4Address("1.2.3.4"), 22,
                                         IPv4Address("4.3.2.1"), 25);

    IP server_packet = IP("1.2.3.4", "4.3.2.1") / TCP(22, 25);
    server_packet.rfind_pdu<TCP>().flags(TCP::RST);
    stream.process_packet(server_packet);

    EXPECT_EQ(Flow::RST_SENT, stream.server_flow().state());
    EXPECT_TRUE(stream.is_finished());
}

TEST_F(FlowTest, StreamFollower_FINClosesStream) {
    using std::placeholders::_1;

    vector<EthernetII> packets = three_way_handshake(29, 60, "1.2.3.4", 22, "4.3.2.1", 25);
    StreamFollower follower;
    follower.new_stream_callback(bind(&FlowTest::on_new_stream, this, _1));
    for (size_t i = 0; i < packets.size(); ++i) {
        follower.process_packet(packets[i]);
    }
    Stream stream = follower.find_stream(IPv4Address("1.2.3.4"), 22,
                                         IPv4Address("4.3.2.1"), 25);

    IP server_packet = IP("1.2.3.4", "4.3.2.1") / TCP(22, 25);
    server_packet.rfind_pdu<TCP>().flags(TCP::FIN | TCP::ACK);
    stream.process_packet(server_packet);

    EXPECT_EQ(Flow::FIN_SENT, stream.server_flow().state());
    EXPECT_FALSE(stream.is_finished());

    IP client_packet = IP("4.3.2.1", "1.2.3.4") / TCP(25, 22);
    client_packet.rfind_pdu<TCP>().flags(TCP::FIN | TCP::ACK);
    stream.process_packet(client_packet);

    EXPECT_EQ(Flow::FIN_SENT, stream.client_flow().state());
    EXPECT_TRUE(stream.is_finished());
}

TEST_F(FlowTest, StreamFollower_StreamIsRemovedWhenFinished) {
    using std::placeholders::_1;

    vector<EthernetII> packets = three_way_handshake(29, 60, "1.2.3.4", 22, "4.3.2.1", 25);
    StreamFollower follower;
    follower.new_stream_callback(bind(&FlowTest::on_new_stream, this, _1));
    for (size_t i = 0; i < packets.size(); ++i) {
        follower.process_packet(packets[i]);
    }
    IP server_packet = IP("1.2.3.4", "4.3.2.1") / TCP(22, 25);
    server_packet.rfind_pdu<TCP>().flags(TCP::RST);
    follower.process_packet(server_packet);

    // We shouldn't be able to find it
    EXPECT_THROW(
        follower.find_stream(IPv4Address("1.2.3.4"), 22, IPv4Address("4.3.2.1"), 25), 
        stream_not_found
    );
}

TEST_F(FlowTest, StreamFollower_FollowStream) {
    using std::placeholders::_1;

    vector<EthernetII> packets = three_way_handshake(29, 60, "1.2.3.4", 22, "4.3.2.1", 25);
    ordering_info_type chunks = split_payload(payload, 5);
    vector<EthernetII> chunk_packets = chunks_to_packets(30 /*initial_seq*/, chunks, payload);
    set_endpoints(chunk_packets, "1.2.3.4", 22, "4.3.2.1", 25);
    packets.insert(packets.end(), chunk_packets.begin(), chunk_packets.end());
    StreamFollower follower;
    follower.new_stream_callback(bind(&FlowTest::on_new_stream, this, _1));
    for (size_t i = 0; i < packets.size(); ++i) {
        follower.process_packet(packets[i]);
    }
    EXPECT_EQ(chunk_packets.size(), stream_client_payload_chunks.size());
    EXPECT_EQ(payload, merge_chunks(stream_client_payload_chunks));
}

#endif // TINS_IS_CXX11
