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
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <thread>
#include <mutex>
#include <atomic>
#include <csignal>
#include <ctime>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <algorithm>
#include <chrono>
#include <deque>
#include <filesystem>

// Linux socket headers
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>
#include <errno.h>
#include <netdb.h>

using namespace std;

// Monitor configuration
struct MonitorConfig {
    int listen_port = 5500;
    string output_file;
    bool color_output = true;
    bool show_stats = true;
    int stats_interval = 10;
    int max_connections = 10;
    bool forward_enabled = true;  // Enable forwarding by default
    string forward_ip = "127.0.0.1";  // Default to localhost - more reliable for initial setup
    int forward_port = 5600;  // Default port for the receiver service
    int connection_retry_interval = 5; // Seconds between connection attempts
    int connection_timeout = 3; // Connection timeout in seconds
};

// Connected agent information
struct AgentInfo {
    int socket;
    string hostname;
    string interface;
    string address;
    time_t connected_time;
    uint64_t packet_count = 0;
    uint64_t byte_count = 0;
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
};

// Statistics
struct Stats {
    map<string, uint64_t> protocol_count;
    map<string, uint64_t> ip_packet_count;
    map<string, uint64_t> ip_byte_count;
    map<int, uint64_t> port_count;
    uint64_t total_packets = 0;
    uint64_t total_bytes = 0;
    
    mutex stats_mutex;
};

// Packet history
struct PacketHistory {
    deque<PacketData> packets;
    mutex history_mutex;
    size_t max_history = 10000;  // Maximum number of packets to keep in history
};

// Globals
atomic<bool> running(true);
vector<AgentInfo> agents;
mutex agents_mutex;
Stats stats;
ofstream output_file;
PacketHistory packet_history;
string csv_export_path = "packet_history.csv";

// External service connection
int forward_socket = -1;
mutex forward_socket_mutex;
bool forward_connected = false;

// ANSI color codes
namespace Color {
    const string RESET   = "\033[0m";
    const string RED     = "\033[31m";
    const string GREEN   = "\033[32m";
    const string YELLOW  = "\033[33m";
    const string BLUE    = "\033[34m";
    const string MAGENTA = "\033[35m";
    const string CYAN    = "\033[36m";
    const string WHITE   = "\033[37m";
    const string BOLD    = "\033[1m";
}

// Signal handler
void signal_handler(int signal) {
    cout << "\nReceived signal " << signal << ". Stopping monitor..." << endl;
    running = false;
}

// Get timestamp
string get_timestamp() {
    auto now = chrono::system_clock::now();
    time_t now_c = chrono::system_clock::to_time_t(now);
    tm *now_tm = localtime(&now_c);
    
    char buffer[64];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", now_tm);
    return string(buffer);
}

// Pretty format for bytes
string format_size(size_t bytes) {
    const char* suffixes[] = {"B", "KB", "MB", "GB"};
    int suffix_index = 0;
    double size = bytes;
    
    while (size >= 1024 && suffix_index < 3) {
        size /= 1024;
        suffix_index++;
    }
    
    ostringstream oss;
    oss << fixed << setprecision(suffix_index > 0 ? 1 : 0) << size << " " << suffixes[suffix_index];
    return oss.str();
}

// Update the connect_to_external_service function to improve connection handling
bool connect_to_external_service(const MonitorConfig& config) {
    lock_guard<mutex> lock(forward_socket_mutex);
    
    // Close existing connection if open
    if (forward_socket >= 0) {
        close(forward_socket);
        forward_socket = -1;
        forward_connected = false;
    }
    
    if (!config.forward_enabled) {
        return false;
    }
    
    cout << "Connecting to external service at " << config.forward_ip << ":" << config.forward_port << "..." << endl;
    
    // Try to resolve the hostname/IP first for better diagnostics
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    char port_str[10];
    snprintf(port_str, sizeof(port_str), "%d", config.forward_port);
    
    int status = getaddrinfo(config.forward_ip.c_str(), port_str, &hints, &res);
    if (status != 0) {
        cerr << "Error resolving address " << config.forward_ip << ": " 
             << gai_strerror(status) << endl;
        return false;
    }
    
    // Extract resolved IP address for diagnostics
    char ip_str[INET_ADDRSTRLEN];
    void *addr;
    struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
    addr = &(ipv4->sin_addr);
    inet_ntop(AF_INET, addr, ip_str, sizeof(ip_str));
    
    cout << "Resolved " << config.forward_ip << " to " << ip_str << endl;
    
    // Create socket
    forward_socket = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (forward_socket < 0) {
        cerr << "Error creating forward socket: " << strerror(errno) << endl;
        freeaddrinfo(res);
        return false;
    }
    
    // Set socket options for better reliability
    int opt = 1;
    if (setsockopt(forward_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        cerr << "Warning: Could not set SO_REUSEADDR for external service" << endl;
    }
    
    // Set socket options
    struct timeval timeout;
    timeout.tv_sec = config.connection_timeout;
    timeout.tv_usec = 0;
    
    if (setsockopt(forward_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0 ||
        setsockopt(forward_socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
        cerr << "Warning: Could not set socket timeout for external service" << endl;
    }

    // Set non-blocking mode for connection
    int flags = fcntl(forward_socket, F_GETFL, 0);
    fcntl(forward_socket, F_SETFL, flags | O_NONBLOCK);
    
    // Try to connect with timeout
    int connect_result = connect(forward_socket, res->ai_addr, res->ai_addrlen);
    
    // Free address info as we don't need it anymore
    freeaddrinfo(res);
    
    if (connect_result < 0 && errno != EINPROGRESS) {
        cerr << "Connection to external service failed immediately: " << strerror(errno) << endl;
        cerr << "Target: " << config.forward_ip << ":" << config.forward_port << endl;
        cerr << "Error code: " << errno << endl;
        
        // Print detailed diagnostic information
        cout << "\nDiagnostic Information:" << endl;
        cout << "- Ensure the receiver service is running on " << config.forward_ip << ":" << config.forward_port << endl;
        cout << "- Check that any firewalls allow outbound connections to port " << config.forward_port << endl;
        cout << "- For public IPs, ensure port forwarding is configured on the router" << endl;
        cout << "- Try testing the connection with:" << endl;
        cout << "  $ nc -zv " << config.forward_ip << " " << config.forward_port << endl;
        cout << "  $ telnet " << config.forward_ip << " " << config.forward_port << endl;
        
        // Check if this is a local connection attempt
        if (config.forward_ip == "127.0.0.1" || config.forward_ip == "localhost") {
            cout << "\nLocal connection troubleshooting:" << endl;
            cout << "- Verify the packet_receiver_service is running on this machine" << endl;
            cout << "- Check if the port is already in use by another application:" << endl;
            cout << "  $ lsof -i :" << config.forward_port << " || netstat -tuln | grep " << config.forward_port << endl;
        }
        // Check if this is a public IP connection attempt
        else if (config.forward_ip != "0.0.0.0" && config.forward_ip != "::1") {
            cout << "\nPublic/Remote IP troubleshooting:" << endl;
            cout << "- Run packet_receiver_service with -d flag for debug mode" << endl;
            cout << "- Ensure receiver service is binding to all interfaces (0.0.0.0)" << endl;
            cout << "- Check router port forwarding for port " << config.forward_port << endl;
            cout << "- Try our connection test script: ./connection_test.sh" << endl;
        }
        
        close(forward_socket);
        forward_socket = -1;
        return false;
    }
    
    if (connect_result < 0) {  // EINPROGRESS
        // Wait for connection completion with select
        fd_set write_fds;
        FD_ZERO(&write_fds);
        FD_SET(forward_socket, &write_fds);
        
        // Set timeout for connection attempt
        struct timeval connect_timeout;
        connect_timeout.tv_sec = config.connection_timeout;
        connect_timeout.tv_usec = 0;
        
        int select_result = select(forward_socket + 1, NULL, &write_fds, NULL, &connect_timeout);
        
        if (select_result <= 0) {
            if (select_result == 0) {
                cerr << "Connection to external service timed out" << endl;
                cerr << "Try increasing the timeout with --connect-timeout" << endl;
            } else {
                cerr << "Error during connection select: " << strerror(errno) << endl;
            }
            close(forward_socket);
            forward_socket = -1;
            return false;
        }
        
        // Check if connection was successful
        int error = 0;
        socklen_t error_len = sizeof(error);
        if (getsockopt(forward_socket, SOL_SOCKET, SO_ERROR, &error, &error_len) < 0 || error != 0) {
            if (error != 0) {
                cerr << "Connection to external service failed: " << strerror(error) << endl;
                cerr << "Target: " << config.forward_ip << ":" << config.forward_port << endl;
            } else {
                cerr << "Error checking connection status: " << strerror(errno) << endl;
            }
            close(forward_socket);
            forward_socket = -1;
            return false;
        }
    }
    
    // Set back to blocking mode for normal operation
    fcntl(forward_socket, F_SETFL, flags);
    
    // Try sending a test message
    string test_msg = "CONNECT_TEST|" + get_timestamp() + "\n";
    if (send(forward_socket, test_msg.c_str(), test_msg.size(), 0) < 0) {
        cerr << "Error sending test message to external service: " << strerror(errno) << endl;
        close(forward_socket);
        forward_socket = -1;
        return false;
    }
    
    // Try to receive acknowledgment
    char ack_buf[64] = {0};
    struct timeval read_timeout;
    read_timeout.tv_sec = 2;  // Short timeout for ack
    read_timeout.tv_usec = 0;
    
    // Use select to wait for data with timeout
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(forward_socket, &read_fds);
    
    if (select(forward_socket + 1, &read_fds, NULL, NULL, &read_timeout) > 0) {
        if (recv(forward_socket, ack_buf, sizeof(ack_buf) - 1, 0) > 0) {
            cout << "Received acknowledgment from receiver service" << endl;
        }
    }
    
    cout << "Successfully connected to external service at " << config.forward_ip << ":" << config.forward_port << endl;
    forward_connected = true;
    return true;
}

// Forward packet data to external service
void forward_packet_data(const PacketData& packet) {
    lock_guard<mutex> lock(forward_socket_mutex);
    
    if (!forward_connected || forward_socket < 0) {
        return;
    }
    
    // Format data for external service
    ostringstream data;
    data << "FORWARD|"
         << packet.timestamp << "|"
         << packet.src_ip << "|" 
         << packet.src_port << "|" 
         << packet.dst_ip << "|" 
         << packet.dst_port << "|" 
         << packet.protocol << "|" 
         << packet.size << "|"
         << packet.agent_hostname << "\n";
    
    string data_str = data.str();
    ssize_t sent = send(forward_socket, data_str.c_str(), data_str.size(), 0);
    
    if (sent < 0) {
        cerr << "Error sending data to external service: " << strerror(errno) << endl;
        close(forward_socket);
        forward_socket = -1;
        forward_connected = false;
    }
}

// Reconnection thread for external service
void external_service_reconnect_thread(const MonitorConfig& config) {
    // Reconnect delay based on config
    int reconnect_delay = config.connection_retry_interval;
    int attempt_count = 0;
    const int max_attempts = 10;  // Limit number of initial connection attempts
    
    while (running && config.forward_enabled) {
        if (!forward_connected) {
            // Increase wait time as we make more attempts
            if (attempt_count > 3) {
                reconnect_delay = config.connection_retry_interval * 2;
            }
            
            cout << "Attempting to connect to external service... (attempt " << ++attempt_count << ")" << endl;
            if (connect_to_external_service(config)) {
                cout << "Connection to external service established" << endl;
                attempt_count = 0;  // Reset attempts counter on success
            } else {
                cout << "Connection to external service failed. Retrying in " 
                     << reconnect_delay << " seconds..." << endl;
                
                // Try alternative IP if public IP fails (automatic fallback)
                if (config.forward_ip != "127.0.0.1" && !forward_connected) {
                    cout << "Trying fallback to localhost (127.0.0.1)..." << endl;
                    MonitorConfig local_config = config;
                    local_config.forward_ip = "127.0.0.1";
                    if (connect_to_external_service(local_config)) {
                        cout << "Connected to local service instead" << endl;
                        attempt_count = 0;  // Reset attempts counter
                    }
                }
            }
        }
        
        // Sleep before next attempt
        for (int i = 0; i < reconnect_delay && running; ++i) {
            this_thread::sleep_for(chrono::seconds(1));
        }
    }
}

// Parse a line of packet data from agent
bool parse_packet_data(const string& line, PacketData& packet, string agent_hostname) {
    vector<string> parts;
    stringstream ss(line);
    string part;
    
    while (getline(ss, part, '|')) {
        parts.push_back(part);
    }
    
    if (parts.size() < 8 || parts[0] != "PACKET") {
        return false;
    }
    
    packet.timestamp = parts[1];
    packet.src_ip = parts[2];
    packet.src_port = atoi(parts[3].c_str());
    packet.dst_ip = parts[4];
    packet.dst_port = atoi(parts[5].c_str());
    packet.protocol = parts[6];
    packet.size = stoul(parts[7]);
    packet.agent_hostname = agent_hostname;
    
    return true;
}

// Process data from an agent
void process_agent_data(int agent_index, const string& data) {
    AgentInfo& agent = agents[agent_index];
    
    // Check if it's agent info
    if (data.substr(0, 10) == "AGENT_INFO") {
        vector<string> parts;
        stringstream ss(data);
        string part;
        
        while (getline(ss, part, '|')) {
            parts.push_back(part);
        }
        
        if (parts.size() >= 3) {
            agent.hostname = parts[1];
            agent.interface = parts[2];
            
            cout << "Agent connected: " << agent.hostname 
                 << " (" << agent.address << ") monitoring interface " 
                 << agent.interface << endl;
        }
        return;
    }
    
    // Process packet data
    PacketData packet;
    if (parse_packet_data(data, packet, agent.hostname)) {
        // Store in history
        {
            lock_guard<mutex> lock(packet_history.history_mutex);
            packet_history.packets.push_back(packet);
            
            // Remove old packets if we exceed max_history
            while (packet_history.packets.size() > packet_history.max_history) {
                packet_history.packets.pop_front();
            }
        }
        
        // Update agent statistics
        agent.packet_count++;
        agent.byte_count += packet.size;
        
        // Update global statistics
        {
            lock_guard<mutex> lock(stats.stats_mutex);
            stats.total_packets++;
            stats.total_bytes += packet.size;
            stats.protocol_count[packet.protocol]++;
            stats.ip_packet_count[packet.src_ip]++;
            stats.ip_byte_count[packet.src_ip] += packet.size;
            
            if (packet.src_port > 0) stats.port_count[packet.src_port]++;
            if (packet.dst_port > 0) stats.port_count[packet.dst_port]++;
        }
        
        // Forward packet to external service if enabled
        if (forward_connected) {
            forward_packet_data(packet);
        }
        
        // Format the output
        ostringstream output;
        output << left << setw(22) << packet.timestamp;
        output << setw(18) << packet.src_ip;
        if (packet.src_port > 0) {
            output << ":" << setw(5) << left << packet.src_port;
        } else {
            output << "     ";
        }
        
        output << " → " << setw(18) << packet.dst_ip;
        if (packet.dst_port > 0) {
            output << ":" << setw(5) << left << packet.dst_port;
        } else {
            output << "     ";
        }
        
        output << " | " << setw(10) << left << packet.protocol;
        output << " | " << setw(10) << right << format_size(packet.size);
        output << " | " << packet.agent_hostname;
        
        string output_str = output.str();
        
        // Print to console with colors
        if (MonitorConfig().color_output) {
            string color;
            if (packet.protocol == "HTTP" || packet.protocol == "HTTPS") {
                color = Color::GREEN;
            } else if (packet.protocol == "DNS") {
                color = Color::CYAN;
            } else if (packet.protocol == "ICMP" || packet.protocol == "ICMPv6") {
                color = Color::YELLOW;
            } else if (packet.protocol == "ARP") {
                color = Color::MAGENTA;
            } else if (packet.protocol.find("TCP") != string::npos) {
                color = Color::BLUE;
            } else if (packet.protocol.find("UDP") != string::npos) {
                color = Color::RED;
            } else {
                color = Color::WHITE;
            }
            
            cout << color << output_str << Color::RESET << endl;
        } else {
            cout << output_str << endl;
        }
        
        // Save to file if enabled
        if (output_file.is_open()) {
            output_file << output_str << endl;
        }
    }
}

// Print statistics
void print_statistics() {
    // Take a snapshot of stats to avoid race conditions
    map<string, uint64_t> protocol_count;
    map<string, uint64_t> ip_packet_count;
    map<string, uint64_t> ip_byte_count;
    map<int, uint64_t> port_count;
    uint64_t total_packets;
    uint64_t total_bytes;
    
    {
        lock_guard<mutex> lock(stats.stats_mutex);
        protocol_count = stats.protocol_count;
        ip_packet_count = stats.ip_packet_count;
        ip_byte_count = stats.ip_byte_count;
        port_count = stats.port_count;
        total_packets = stats.total_packets;
        total_bytes = stats.total_bytes;
    }
    
    cout << "\n===== Network Monitor Statistics =====" << endl;
    cout << "Total Packets: " << total_packets << endl;
    cout << "Total Data: " << format_size(total_bytes) << endl;
    
    // Connected agents
    {
        lock_guard<mutex> lock(agents_mutex);
        cout << "\nConnected Agents (" << agents.size() << "):" << endl;
        for (const auto& agent : agents) {
            cout << "  " << agent.hostname << " (" << agent.address << ") - " 
                 << agent.packet_count << " packets, " 
                 << format_size(agent.byte_count) << endl;
        }
    }
    
    // Protocol statistics
    cout << "\nTop Protocols:" << endl;
    vector<pair<string, uint64_t>> protocol_vec(protocol_count.begin(), protocol_count.end());
    sort(protocol_vec.begin(), protocol_vec.end(), 
         [](const pair<string, uint64_t>& a, const pair<string, uint64_t>& b) { 
             return a.second > b.second; 
         });
    
    for (size_t i = 0; i < min(size_t(5), protocol_vec.size()); ++i) {
        cout << "  " << setw(10) << left << protocol_vec[i].first << ": " 
             << protocol_vec[i].second << " packets";
        if (total_packets > 0) {
            cout << " (" << fixed << setprecision(1) 
                 << (protocol_vec[i].second * 100.0 / total_packets) << "%)";
        }
        cout << endl;
    }
    
    // IP address statistics
    cout << "\nTop Source IPs:" << endl;
    vector<pair<string, uint64_t>> ip_vec(ip_packet_count.begin(), ip_packet_count.end());
    sort(ip_vec.begin(), ip_vec.end(), 
         [](const pair<string, uint64_t>& a, const pair<string, uint64_t>& b) { 
             return a.second > b.second; 
         });
    
    for (size_t i = 0; i < min(size_t(5), ip_vec.size()); ++i) {
        cout << "  " << setw(18) << left << ip_vec[i].first << ": " 
             << ip_vec[i].second << " packets, "
             << format_size(ip_byte_count[ip_vec[i].first]) << endl;
    }
    
    // Port statistics
    cout << "\nTop Ports:" << endl;
    vector<pair<int, uint64_t>> port_vec(port_count.begin(), port_count.end());
    sort(port_vec.begin(), port_vec.end(), 
         [](const pair<int, uint64_t>& a, const pair<int, uint64_t>& b) { 
             return a.second > b.second; 
         });
    
    for (size_t i = 0; i < min(size_t(5), port_vec.size()); ++i) {
        string port_service = to_string(port_vec[i].first);
        // Add known service names for common ports
        if (port_vec[i].first == 80) port_service += " (HTTP)";
        else if (port_vec[i].first == 443) port_service += " (HTTPS)";
        else if (port_vec[i].first == 53) port_service += " (DNS)";
        else if (port_vec[i].first == 22) port_service += " (SSH)";
        
        cout << "  Port " << setw(15) << left << port_service << ": " 
             << port_vec[i].second << " uses" << endl;
    }
    
    cout << endl;
}

// Handle agent connections and data
void handle_agents(int server_socket, const MonitorConfig& config) {
    fd_set read_fds, master_fds;
    FD_ZERO(&master_fds);
    FD_SET(server_socket, &master_fds);
    
    int max_fd = server_socket;
    
    // For reading data from clients
    char buffer[4096];
    vector<string> incomplete_data(config.max_connections + 1);
    
    while (running) {
        // Copy the master set to read_fds
        read_fds = master_fds;
        
        // Set up timeout
        struct timeval timeout;
        timeout.tv_sec = 1;  // 1 second timeout for clean exit
        timeout.tv_usec = 0;
        
        // Wait for activity on any socket
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
                // Add to agents list
                AgentInfo agent;
                agent.socket = client_socket;
                agent.address = inet_ntoa(client_addr.sin_addr);
                agent.connected_time = time(NULL);
                
                {
                    lock_guard<mutex> lock(agents_mutex);
                    agents.push_back(agent);
                }
                
                // Add to master set
                FD_SET(client_socket, &master_fds);
                if (client_socket > max_fd) {
                    max_fd = client_socket;
                }
                
                cout << "New connection from " << agent.address << endl;
            }
        }
        
        // Check data from agents
        {
            lock_guard<mutex> lock(agents_mutex);
            
            for (size_t i = 0; i < agents.size(); ++i) {
                int client_socket = agents[i].socket;
                
                if (FD_ISSET(client_socket, &read_fds)) {
                    // Receive data
                    memset(buffer, 0, sizeof(buffer));
                    int bytes_read = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
                    
                    if (bytes_read <= 0) {
                        // Connection closed or error
                        cout << "Agent disconnected: " << agents[i].hostname 
                             << " (" << agents[i].address << ")" << endl;
                        
                        close(client_socket);
                        FD_CLR(client_socket, &master_fds);
                        
                        // Remove from agents list
                        agents.erase(agents.begin() + i);
                        i--; // Adjust index
                    } else {
                        // Process received data
                        buffer[bytes_read] = '\0';
                        string data = incomplete_data[i] + buffer;
                        
                        // Process complete lines
                        size_t pos = 0;
                        while ((pos = data.find('\n')) != string::npos) {
                            string line = data.substr(0, pos);
                            data = data.substr(pos + 1);
                            
                            // Process the complete line
                            process_agent_data(i, line);
                        }
                        
                        // Save any incomplete data
                        incomplete_data[i] = data;
                    }
                }
            }
        }
    }
}

// Parse command line arguments
void parse_arguments(int argc, char* argv[], MonitorConfig& config) {
    for (int i = 1; i < argc; ++i) {
        string arg = argv[i];
        
        if (arg == "-h" || arg == "--help") {
            cout << "Packet Monitor Server - Receive and display network packets from agents" << endl;
            cout << "Usage: " << argv[0] << " [options]" << endl;
            cout << "Options:" << endl;
            cout << "  -p, --port PORT       Listen on port (default: 5500)" << endl;
            cout << "  -o, --output FILE     Save packet data to file" << endl;
            cout << "  -n, --no-color        Disable colored output" << endl;
            cout << "  -s, --no-stats        Disable statistics" << endl;
            cout << "  -i, --interval SEC    Statistics display interval (default: 10)" << endl;
            cout << "  -f, --forward IP:PORT Forward packets to external service (default: 127.0.0.1:5600)" << endl;
            cout << "  --no-forward          Disable packet forwarding" << endl;
            cout << "  --connect-retry SEC   Connection retry interval (default: 5 seconds)" << endl;
            cout << "  --connect-timeout SEC Connection timeout (default: 3 seconds)" << endl;
            cout << "  --local               Force use of localhost (127.0.0.1) for forwarding" << endl;
            exit(0);
        } else if ((arg == "-p" || arg == "--port") && i + 1 < argc) {
            config.listen_port = atoi(argv[++i]);
        } else if ((arg == "-o" || arg == "--output") && i + 1 < argc) {
            config.output_file = argv[++i];
        } else if (arg == "-n" || arg == "--no-color") {
            config.color_output = false;
        } else if (arg == "-s" || arg == "--no-stats") {
            config.show_stats = false;
        } else if ((arg == "-i" || arg == "--interval") && i + 1 < argc) {
            config.stats_interval = atoi(argv[++i]);
        } else if ((arg == "-f" || arg == "--forward") && i + 1 < argc) {
            config.forward_enabled = true;
            string forward_address = argv[++i];
            size_t colon_pos = forward_address.find(':');
            if (colon_pos != string::npos) {
                config.forward_ip = forward_address.substr(0, colon_pos);
                config.forward_port = atoi(forward_address.substr(colon_pos + 1).c_str());
            } else {
                cerr << "Invalid forward address format. Use IP:PORT format." << endl;
                exit(1);
            }
        } else if (arg == "--no-forward") {
            config.forward_enabled = false;
        } else if (arg == "--local") {
            config.forward_ip = "127.0.0.1";
        } else if (arg == "--connect-retry" && i + 1 < argc) {
            config.connection_retry_interval = atoi(argv[++i]);
        } else if (arg == "--connect-timeout" && i + 1 < argc) {
            config.connection_timeout = atoi(argv[++i]);
        }
    }
}

// Add new function for CSV export
void export_to_csv(const string& filename) {
    lock_guard<mutex> lock(packet_history.history_mutex);
    
    ofstream csv_file(filename);
    if (!csv_file.is_open()) {
        cerr << "Error: Could not open CSV file for writing: " << filename << endl;
        return;
    }
    
    // Write CSV header
    csv_file << "Timestamp,Source IP,Source Port,Destination IP,Destination Port,Protocol,Size (bytes),Agent Hostname" << endl;
    
    // Write packet data
    for (const auto& packet : packet_history.packets) {
        csv_file << packet.timestamp << ","
                 << packet.src_ip << ","
                 << packet.src_port << ","
                 << packet.dst_ip << ","
                 << packet.dst_port << ","
                 << packet.protocol << ","
                 << packet.size << ","
                 << packet.agent_hostname << endl;
    }
    
    csv_file.close();
    cout << "Packet history exported to " << filename << endl;
}

// Add new function to handle export command
void handle_export_command(const string& command) {
    vector<string> parts;
    stringstream ss(command);
    string part;
    
    while (getline(ss, part, ' ')) {
        parts.push_back(part);
    }
    
    if (parts.size() >= 2 && parts[0] == "export") {
        string filename = parts[1];
        if (filename.empty()) {
            filename = csv_export_path;
        }
        export_to_csv(filename);
    }
}

// Add command handling to the main loop
void handle_commands() {
    string command;
    while (running) {
        if (getline(cin, command)) {
            if (command == "export" || command.substr(0, 7) == "export ") {
                handle_export_command(command);
            } else if (command == "help") {
                cout << "\nAvailable commands:" << endl;
                cout << "  export [filename]  - Export packet history to CSV file" << endl;
                cout << "  help              - Show this help message" << endl;
                cout << "  quit              - Exit the program" << endl;
            } else if (command == "quit") {
                running = false;
            }
        }
    }
}

int main(int argc, char* argv[]) {
    // Register signal handler
    signal(SIGINT, signal_handler);
    
    // Default configuration
    MonitorConfig config;
    parse_arguments(argc, argv, config);
    
    // Open output file if specified
    if (!config.output_file.empty()) {
        output_file.open(config.output_file);
        if (!output_file.is_open()) {
            cerr << "Error: Could not open output file '" << config.output_file << "'" << endl;
            return 1;
        }
    }
    
    // Create server socket
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        cerr << "Error creating server socket" << endl;
        return 1;
    }
    
    // Set socket options for reuse
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        cerr << "Error setting socket options" << endl;
        close(server_socket);
        return 1;
    }
    
    // Bind socket to port
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(config.listen_port);
    
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        cerr << "Error binding server socket to port " << config.listen_port << ": " << strerror(errno) << endl;
        close(server_socket);
        return 1;
    }
    
    // Listen for connections
    if (listen(server_socket, config.max_connections) < 0) {
        cerr << "Error listening on server socket: " << strerror(errno) << endl;
        close(server_socket);
        return 1;
    }
    
    cout << "Packet Monitor Server started" << endl;
    cout << "Listening for agent connections on port " << config.listen_port << endl;
    
    if (!config.output_file.empty()) {
        cout << "Saving packet data to '" << config.output_file << "'" << endl;
    }
    
    // Initialize external service connection if enabled
    thread external_service_thread;
    if (config.forward_enabled) {
        cout << "Forwarding packets to external service at " 
             << config.forward_ip << ":" << config.forward_port << endl;
        
        // Initial connection attempt
        if (connect_to_external_service(config)) {
            cout << "Successfully connected to external service" << endl;
        } else {
            cout << "Initial connection to external service failed. Will retry in background..." << endl;
        }
        
        // Start reconnection thread
        external_service_thread = thread(external_service_reconnect_thread, config);
    } else {
        cout << "Packet forwarding is disabled" << endl;
    }
    
    cout << "\nAvailable commands:" << endl;
    cout << "  export [filename]  - Export packet history to CSV file" << endl;
    cout << "  help              - Show this help message" << endl;
    cout << "  quit              - Exit the program" << endl;
    cout << "\nPress Ctrl+C to stop" << endl << endl;
    
    // Print column headers
    cout << left << setw(22) << "TIMESTAMP";
    cout << setw(24) << "SOURCE";
    cout << setw(24) << "DESTINATION";
    cout << setw(11) << "PROTOCOL";
    cout << setw(11) << "SIZE";
    cout << "AGENT" << endl;
    
    cout << string(100, '-') << endl;
    
    // Create command handling thread
    thread command_thread(handle_commands);
    
    // Create statistics thread
    thread stats_thread;
    if (config.show_stats) {
        stats_thread = thread([&config]() {
            while (running) {
                for (int i = 0; i < config.stats_interval && running; ++i) {
                    this_thread::sleep_for(chrono::seconds(1));
                }
                
                if (running && stats.total_packets > 0) {
                    print_statistics();
                }
            }
        });
    }
    
    // Handle agent connections
    handle_agents(server_socket, config);
    
    // Wait for threads to finish
    if (command_thread.joinable()) {
        command_thread.join();
    }
    
    if (config.show_stats && stats_thread.joinable()) {
        stats_thread.join();
    }
    
    if (config.forward_enabled && external_service_thread.joinable()) {
        external_service_thread.join();
    }
    
    // Export final packet history before exit
    export_to_csv(csv_export_path);
    
    // Clean up
    close(server_socket);
    
    if (forward_socket >= 0) {
        close(forward_socket);
    }
    
    if (output_file.is_open()) {
        output_file.close();
    }
    
    // Close any open agent connections
    {
        lock_guard<mutex> lock(agents_mutex);
        for (const auto& agent : agents) {
            close(agent.socket);
        }
    }
    
    cout << "\nPacket Monitor Server stopped" << endl;
    
    return 0;
}