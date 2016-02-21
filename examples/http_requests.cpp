/*
 * Copyright (c) 2016, Matias Fontanini
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following disclaimer
 *   in the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <string>
#include <iostream>
#include <stdexcept>
#include <boost/regex.hpp>
#include "tins/tcp_ip/stream_follower.h"
#include "tins/sniffer.h"

using std::string;
using std::cout;
using std::cerr;
using std::endl;
using std::exception;

using boost::regex;
using boost::match_results;

using Tins::PDU;
using Tins::Sniffer;
using Tins::SnifferConfiguration;
using Tins::TCPIP::Stream;
using Tins::TCPIP::StreamFollower;

// This example captures and follows TCP streams seen on port 80. It will
// wait until both the client and server send data and then apply a regex
// to both payloads, extrating some information and printing it.

// Don't buffer more than 3kb of data in either request/response
const size_t MAX_PAYLOAD = 3 * 1024;
// The regex to be applied on the request. This will extract the HTTP
// method being used, the request's path and the Host header value.
regex request_regex("([\\w]+) ([^ ]+).+\r\nHost: ([\\d\\w\\.-]+)\r\n");
// The regex to be applied on the response. This finds the response code.
regex response_regex("HTTP/[^ ]+ ([\\d]+)");

void on_server_data(Stream& stream) {
    match_results<Stream::payload_type::const_iterator> client_match;
    match_results<Stream::payload_type::const_iterator> server_match;
    const Stream::payload_type& client_payload = stream.client_payload();
    const Stream::payload_type& server_payload = stream.server_payload();
    // Run the regexes on client/server payloads
    bool valid = regex_search(server_payload.begin(), server_payload.end(),
                              server_match, response_regex) &&
                 regex_search(client_payload.begin(), client_payload.end(),
                              client_match, request_regex);
    // If we matched both the client and the server regexes
    if (valid) {
        // Extract all fields
        string method = string(client_match[1].first, client_match[1].second);
        string url = string(client_match[2].first, client_match[2].second);
        string host = string(client_match[3].first, client_match[3].second);
        string response_code = string(server_match[1].first, server_match[1].second);
        // Now print them
        cout << method << " http://" << host << url << " -> " << response_code << endl;

        // Once we've seen the first request on this stream, ignore it
        stream.ignore_client_data();
        stream.ignore_server_data();
    }
    
    // Just in case the server returns invalid data, stop at 3kb
    if (stream.server_payload().size() > MAX_PAYLOAD) {
        stream.ignore_server_data();
    }
}

void on_client_data(Stream& stream) {
    // Don't hold more than 3kb of data from the client's flow
    if (stream.client_payload().size() > MAX_PAYLOAD) {
        stream.ignore_client_data();
    }
}

void on_new_connection(Stream& stream) {
    stream.client_data_callback(&on_client_data);
    stream.server_data_callback(&on_server_data);
    // Don't automatically cleanup the stream's data, as we'll manage
    // the buffer ourselves and let it grow until we see a full request
    // and response
    stream.auto_cleanup_payloads(false);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        cout << "Usage: " << argv[0] << " <interface>" << endl;
        return 1;
    }

    try {
        // Construct the sniffer configuration object
        SnifferConfiguration config;
        // Get packets as quickly as possible
        config.set_immediate_mode(true);
        // Only capture TCP traffic sent from/to port 80
        config.set_filter("tcp port 80");
        // Construct the sniffer we'll use
        Sniffer sniffer(argv[1], config);

        cout << "Starting capture on interface " << argv[1] << endl;

        // Now construct the stream follower
        StreamFollower follower;
        // We just need to specify the callback to be executed when a new 
        // stream is captured. In this stream, you should define which callbacks
        // will be executed whenever new data is sent on that stream 
        // (see on_new_connection)
        follower.new_stream_callback(&on_new_connection);
        // Now start capturing. Every time there's a new packet, call 
        // follower.process_packet
        sniffer.sniff_loop([&](PDU& packet) {
            follower.process_packet(packet);
            return true;
        });
    }
    catch (exception& ex) {
        cerr << "Error: " << ex.what() << endl;
        return 1;
    }
}
