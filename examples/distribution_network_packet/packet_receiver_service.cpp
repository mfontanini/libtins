/*
 * Copyright (c) 2023, Muhammad Gilang Ramadhan
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

#include <iostream>
#include <string>
#include <cstring>
#include <csignal>
#include <atomic>
#include <thread>
#include <mutex>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <vector>
#include <functional>

// Socket headers
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>
#include <errno.h>
#include <netdb.h>

using namespace std;

// Configuration
struct Config {
    int listen_port = 5600;
    string output_file = "received_packets.log";
    bool verbose = false;
    bool bind_all_interfaces = true;  // By default, bind to all interfaces
    string bind_address = "0.0.0.0";  // Default address to bind to (all interfaces)
    bool debug_mode = false;          // Add debug mode for detailed connection info
};

// Packet data structure
struct PacketData {
    string timestamp;
    string src_ip;
    int src_port;
    string dst_ip;
    int dst_port;
    string protocol;
    size_t size;
    string agent_hostname;
    
    // Parse from incoming data string
    static bool parse(const string& data, PacketData& packet) {
        if (data.substr(0, 8) != "FORWARD|") {
            return false;
        }
        
        vector<string> parts;
        stringstream ss(data);
        string part;
        
        while (getline(ss, part, '|')) {
            parts.push_back(part);
        }
        
        // Ensure we have all parts
        if (parts.size() < 9) {
            return false;
        }
        
        packet.timestamp = parts[1];
        packet.src_ip = parts[2];
        packet.src_port = stoi(parts[3]);
        packet.dst_ip = parts[4];
        packet.dst_port = stoi(parts[5]);
        packet.protocol = parts[6];
        packet.size = stoull(parts[7]);
        packet.agent_hostname = parts[8];
        
        return true;
    }
    
    // Convert to string representation
    string to_string() const {
        ostringstream ss;
        ss << "[" << timestamp << "] " 
           << src_ip << ":" << src_port << " -> " 
           << dst_ip << ":" << dst_port 
           << " (" << protocol << ", " << size << " bytes) "
           << "from " << agent_hostname;
        return ss.str();
    }
};

// Function type for packet processing
typedef function<void(const PacketData&)> PacketProcessor;

// Global variables
atomic<bool> running(true);
ofstream log_file;

// Signal handler
void signal_handler(int signal) {
    cout << "Received signal " << signal << ". Stopping receiver..." << endl;
    running = false;
}

// Process received packets
void process_packet(const PacketData& packet, const Config& config) {
    string packet_str = packet.to_string();
    
    // Print to console if verbose
    if (config.verbose) {
        cout << "Received: " << packet_str << endl;
    }
    
    // Write to log file
    if (log_file.is_open()) {
        log_file << packet_str << endl;
        log_file.flush();  // Ensure it's written immediately
    }
    
    // Additional processing could be added here:
    // - Send to a database
    // - Process for alerts
    // - Forward to another service
    // - etc.
}

// Handle client connections
void handle_client(int client_socket, const Config& config) {
    char buffer[4096];
    string incomplete_data;
    
    // Get client address info
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    getpeername(client_socket, (struct sockaddr*)&client_addr, &addr_len);
    string client_ip = inet_ntoa(client_addr.sin_addr);
    
    // Log the successful connection
    cout << "Client connected from " << client_ip << " - waiting for data..." << endl;
    
    while (running) {
        // Receive data
        memset(buffer, 0, sizeof(buffer));
        int bytes_read = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
        
        if (bytes_read <= 0) {
            // Connection closed or error
            if (bytes_read < 0) {
                cerr << "Error receiving data from " << client_ip << ": " << strerror(errno) << endl;
            } else {
                cout << "Client " << client_ip << " disconnected" << endl;
            }
            break;
        }
        
        // Process received data
        buffer[bytes_read] = '\0';
        string data = incomplete_data + buffer;
        
        // Process complete lines
        size_t pos = 0;
        while ((pos = data.find('\n')) != string::npos) {
            string line = data.substr(0, pos);
            data = data.substr(pos + 1);
            
            // Check if it's a connection test
            if (line.substr(0, 13) == "CONNECT_TEST|") {
                cout << "Received connection test from " << client_ip << endl;
                
                // Send acknowledgment for connection test
                string ack = "ACK_CONNECT_TEST\n";
                send(client_socket, ack.c_str(), ack.size(), 0);
                continue;  // Skip further processing
            }
            
            // Parse and process packet data
            PacketData packet;
            if (PacketData::parse(line, packet)) {
                process_packet(packet, config);
            } else {
                cerr << "Failed to parse packet data: " << line << endl;
            }
        }
        
        // Save any incomplete data for next time
        incomplete_data = data;
    }
    
    close(client_socket);
}

// Parse command line arguments
void parse_arguments(int argc, char* argv[], Config& config) {
    for (int i = 1; i < argc; ++i) {
        string arg = argv[i];
        
        if (arg == "-h" || arg == "--help") {
            cout << "Packet Receiver Service - Receive forwarded packets from monitor server" << endl;
            cout << "Usage: " << argv[0] << " [options]" << endl;
            cout << "Options:" << endl;
            cout << "  -p, --port PORT       Listen on port (default: 5600)" << endl;
            cout << "  -o, --output FILE     Save packet data to file (default: received_packets.log)" << endl;
            cout << "  -v, --verbose         Show all packets on console" << endl;
            cout << "  -a, --address IP      Bind to specific IP address (default: 0.0.0.0)" << endl;
            cout << "  -d, --debug           Enable debug mode with extra connection information" << endl;
            exit(0);
        } else if ((arg == "-p" || arg == "--port") && i + 1 < argc) {
            config.listen_port = atoi(argv[++i]);
        } else if ((arg == "-o" || arg == "--output") && i + 1 < argc) {
            config.output_file = argv[++i];
        } else if (arg == "-v" || arg == "--verbose") {
            config.verbose = true;
        } else if ((arg == "-a" || arg == "--address") && i + 1 < argc) {
            config.bind_all_interfaces = false;
            config.bind_address = argv[++i];
        } else if (arg == "-d" || arg == "--debug") {
            config.debug_mode = true;
        }
    }
}

// Function to print network interfaces
void print_network_interfaces() {
    cout << "\nAvailable network interfaces:" << endl;
    cout << "----------------------------" << endl;
    
    // Try different commands depending on availability
    if (system("ip -br addr") != 0) {
        if (system("ifconfig") != 0) {
            system("ipconfig"); // Try Windows command
        }
    }
    
    cout << endl;
}

// Function to check port availability
bool check_port_availability(int port) {
    int test_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (test_socket < 0) {
        cerr << "Error creating test socket: " << strerror(errno) << endl;
        return false;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    // Try to bind to the port
    int bind_result = ::bind(test_socket, (struct sockaddr*)&addr, sizeof(addr));
    close(test_socket);
    
    if (bind_result < 0) {
        return false; // Port is in use
    }
    
    return true; // Port is available
}

int main(int argc, char* argv[]) {
    // Register signal handler
    signal(SIGINT, signal_handler);
    
    // Default configuration
    Config config;
    parse_arguments(argc, argv, config);
    
    // Open log file
    log_file.open(config.output_file, ios::app);  // Append to existing file
    if (!log_file.is_open()) {
        cerr << "Error: Could not open log file '" << config.output_file << "'" << endl;
        return 1;
    }
    
    // Print network configuration if debug mode enabled
    if (config.debug_mode) {
        cout << "\n=== Network Configuration ===" << endl;
        print_network_interfaces();
        
        // Check for port availability
        if (!check_port_availability(config.listen_port)) {
            cerr << "Warning: Port " << config.listen_port << " may already be in use!" << endl;
            cout << "Processes using this port:" << endl;
            system(("lsof -i :" + to_string(config.listen_port) + " || netstat -tuln | grep " + to_string(config.listen_port)).c_str());
            cout << endl;
        }
    }
    
    // Create server socket
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        cerr << "Error creating server socket: " << strerror(errno) << endl;
        return 1;
    }
    
    // Set socket options for reuse
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        cerr << "Error setting socket options: " << strerror(errno) << endl;
        close(server_socket);
        return 1;
    }
    
    // Bind socket to port
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    
    // Bind to specific address or all interfaces
    if (config.bind_all_interfaces) {
        server_addr.sin_addr.s_addr = INADDR_ANY;  // Listen on all interfaces
    } else {
        if (inet_pton(AF_INET, config.bind_address.c_str(), &server_addr.sin_addr) <= 0) {
            cerr << "Error: Invalid address to bind: " << config.bind_address << endl;
            close(server_socket);
            return 1;
        }
    }
    
    server_addr.sin_port = htons(config.listen_port);
    
    if (::bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        cerr << "Error binding server socket to port " << config.listen_port << ": " << strerror(errno) << endl;
        cerr << "You may need to wait a minute for the port to be released if it was recently used." << endl;
        cerr << "Alternatively, try a different port with the -p option." << endl;
        close(server_socket);
        return 1;
    }
    
    // Listen for connections
    if (listen(server_socket, 5) < 0) {
        cerr << "Error listening on server socket: " << strerror(errno) << endl;
        close(server_socket);
        return 1;
    }
    
    cout << "Packet Receiver Service started" << endl;
    cout << "Listening for forwarded packets on " << (config.bind_all_interfaces ? "all interfaces (0.0.0.0)" : config.bind_address) 
         << ":" << config.listen_port << endl;
    
    // Print network interfaces for diagnostic purposes
    print_network_interfaces();
    
    cout << "\nSaving packet data to '" << config.output_file << "'" << endl;
    
    // Check for port availability and conflicts
    if (!check_port_availability(config.listen_port)) {
        cout << "Note: Another process might be using the same port. The service may not work correctly." << endl;
    }
    
    cout << "Press Ctrl+C to stop" << endl << endl;
    
    // Connection guide
    cout << "Connection guide:" << endl;
    cout << "- For local connection: ./packet_monitor_server --local" << endl;
    cout << "- For remote connection: ./packet_monitor_server -f YOUR_IP:" << config.listen_port << endl;
    cout << endl;
    
    // Print firewall warning
    cout << "=== Important ===" << endl;
    cout << "If connecting from a different machine:" << endl;
    cout << "1. Ensure this port is open in your firewall" << endl;
    cout << "2. If using a public IP, set up port forwarding on your router" << endl;
    cout << "3. Test connectivity with: nc -zv YOUR_IP " << config.listen_port << endl;
    cout << endl;

    // Server loop
    fd_set read_fds, master_fds;
    FD_ZERO(&master_fds);
    FD_SET(server_socket, &master_fds);
    int max_fd = server_socket;
    
    vector<thread> client_threads;
    
    while (running) {
        // Copy the master set to read_fds
        read_fds = master_fds;
        
        // Set up timeout for select
        struct timeval timeout;
        timeout.tv_sec = 1;  // 1 second timeout for clean exit
        timeout.tv_usec = 0;
        
        // Wait for activity
        int activity = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);
        
        if (activity < 0 && errno != EINTR) {
            cerr << "Select error: " << strerror(errno) << endl;
            break;
        }
        
        // Check for new connections
        if (FD_ISSET(server_socket, &read_fds)) {
            struct sockaddr_in client_addr;
            socklen_t addr_len = sizeof(client_addr);
            
            int client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &addr_len);
            if (client_socket >= 0) {
                // Log the connection
                cout << "New connection from " << inet_ntoa(client_addr.sin_addr) 
                     << ":" << ntohs(client_addr.sin_port) << endl;
                
                // Start a thread to handle this client
                client_threads.push_back(thread(handle_client, client_socket, config));
            } else {
                cerr << "Error accepting connection: " << strerror(errno) << endl;
            }
        }
    }
    
    // Clean up
    cout << "Waiting for client threads to finish..." << endl;
    for (auto& t : client_threads) {
        if (t.joinable()) {
            t.join();
        }
    }
    
    close(server_socket);
    
    if (log_file.is_open()) {
        log_file.close();
    }
    
    cout << "Packet Receiver Service stopped" << endl;
    
    return 0;
} 