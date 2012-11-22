#include <cstring>
#include <cassert>
#ifndef WIN32
    #include <netinet/in.h>
    #include <sys/socket.h>
#endif
#include "ipv6.h"
#include "constants.h"
#include "packet_sender.h"
#include "ip.h"
#include "tcp.h"
#include "udp.h"
#include "icmp.h"
#include "rawpdu.h"

namespace Tins {

IPv6::IPv6(address_type ip_dst, address_type ip_src, PDU *child) {
    std::memset(&_header, 0, sizeof(_header));
    version(6);
    dst_addr(ip_dst);
    src_addr(ip_src);
}

IPv6::IPv6(const uint8_t *buffer, uint32_t total_sz) {
    if(total_sz < sizeof(_header))
        throw std::runtime_error("Not enough size for an IPv6 PDU");
    std::memcpy(&_header, buffer, sizeof(_header));
    buffer += sizeof(_header);
    total_sz -= sizeof(_header);
    if (total_sz) {
        switch(_header.next_header) {
            case Constants::IP::PROTO_TCP:
                inner_pdu(new Tins::TCP(buffer, total_sz));
                break;
            case Constants::IP::PROTO_UDP:
                inner_pdu(new Tins::UDP(buffer, total_sz));
                break;
            case Constants::IP::PROTO_ICMP:
                inner_pdu(new Tins::ICMP(buffer, total_sz));
                break;
            default:
                inner_pdu(new Tins::RawPDU(buffer, total_sz));
                break;
        }
    }
}

void IPv6::version(small_uint<4> new_version) {
    _header.version = new_version;
}

void IPv6::traffic_class(uint8_t new_traffic_class) {
    #if TINS_IS_LITTLE_ENDIAN
    _header.traffic_class = (new_traffic_class >> 4) & 0xf;
    _header.flow_label[0] = (_header.flow_label[0] & 0x0f) | ((new_traffic_class << 4) & 0xf0);
    #else
    _header.traffic_class = new_traffic_class;
    #endif
}

void IPv6::flow_label(small_uint<20> new_flow_label) {
    #if TINS_IS_LITTLE_ENDIAN
    uint32_t value = Endian::host_to_be<uint32_t>(new_flow_label);
    _header.flow_label[2] = (value >> 24) & 0xff;
    _header.flow_label[1] = (value >> 16) & 0xff;
    _header.flow_label[0] = ((value >> 8) & 0x0f) | (_header.flow_label[0] & 0xf0);
    #else
    _header.flow_label = new_flow_label;
    #endif
}

void IPv6::payload_length(uint16_t new_payload_length) {
    _header.payload_length = Endian::host_to_be(new_payload_length);
}

void IPv6::next_header(uint8_t new_next_header) {
    _header.next_header = new_next_header;
}

void IPv6::hop_limit(uint8_t new_hop_limit) {
    _header.hop_limit = new_hop_limit;
}

void IPv6::src_addr(const address_type &new_src_addr) {
    new_src_addr.copy(_header.src_addr);
}

void IPv6::dst_addr(const address_type &new_dst_addr) {
    new_dst_addr.copy(_header.dst_addr);
}

uint32_t IPv6::header_size() const {
    return sizeof(_header);
}

void IPv6::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent) {
    assert(total_sz >= sizeof(_header));
    if(inner_pdu()) {
        uint8_t new_flag;
        switch(inner_pdu()->pdu_type()) {
            case PDU::IP:
                new_flag = Constants::IP::PROTO_IPIP;
                break;
            case PDU::TCP:
                new_flag = Constants::IP::PROTO_TCP;
                break;
            case PDU::UDP:
                new_flag = Constants::IP::PROTO_UDP;
                break;
            case PDU::ICMP:
                new_flag = Constants::IP::PROTO_ICMP;
                break;
            default:
                // check for other protos
                new_flag = 0xff;
        };
        next_header(new_flag);
    }
    payload_length(total_sz - sizeof(_header));
    std::memcpy(buffer, &_header, sizeof(_header));
}

void IPv6::send(PacketSender &sender) {
    struct sockaddr_in6 link_addr;
    PacketSender::SocketType type = PacketSender::IPV6_SOCKET;
    link_addr.sin6_family = AF_INET6;
    link_addr.sin6_port = 0;
    std::copy(_header.dst_addr, _header.dst_addr + address_type::address_size, (uint8_t*)&link_addr.sin6_addr);
    if(inner_pdu() && inner_pdu()->pdu_type() == PDU::ICMP)
        type = PacketSender::ICMP_SOCKET;

    sender.send_l3(*this, (struct sockaddr*)&link_addr, sizeof(link_addr), type);
}

}
