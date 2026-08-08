# Network Packet Monitoring System

This system consists of three components:

1. **Packet Agent** - Captures network packets and sends them to the monitor server
2. **Packet Monitor Server** - Receives, displays, and processes packet data from agents
3. **Packet Receiver Service** - Receives forwarded packet data from the monitor server

## Environment Requirements

### Linux/Unix
- C++17 compatible compiler (GCC 7+ or Clang 5+)
- libtins library (for packet_agent)
- libpcap development files
- pthread library
- openssl development files

### macOS
- Xcode Command Line Tools
- Homebrew (recommended for installing dependencies)
- libtins library

### Windows
- Visual Studio 2019+ with C++ development tools
- WinPcap or Npcap
- CMake 3.13+

## Installation

### Linux Installation

```bash
# Debian/Ubuntu
sudo apt-get install build-essential cmake libpcap-dev libssl-dev
sudo apt-get install libtins-dev

# Fedora/RHEL/CentOS
sudo dnf install gcc-c++ cmake libpcap-devel openssl-devel
sudo dnf install libtins-devel
```

### macOS Installation

```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install cmake libtins libpcap openssl
```

### Windows Installation

1. Install [Visual Studio](https://visualstudio.microsoft.com/downloads/) with C++ development tools
2. Install [CMake](https://cmake.org/download/)
3. Install [WinPcap](https://www.winpcap.org/install/) or [Npcap](https://nmap.org/npcap/)
4. Build using provided `build_windows.bat` script

## Building the System

### Using Make (Linux/Unix/macOS)

```bash
make
```

This will generate three executables:
- `packet_agent`
- `packet_monitor_server`
- `packet_receiver_service`

### Using CMake (Cross-platform)

```bash
mkdir build
cd build
cmake ..
cmake --build . --config Release
```

### macOS Specific Compilation

```bash
# Use the provided macOS compilation script
chmod +x mac_compile.sh
./mac_compile.sh
```

### Windows Compilation

```batch
# Run the Windows build script
build_windows.bat
```

## Basic Usage

### Step 1: Start the Packet Receiver Service

```bash
./packet_receiver_service [options]
```

Options:
- `-p, --port PORT` - Listen port (default: 5600)
- `-o, --output FILE` - Log file (default: received_packets.log)
- `-v, --verbose` - Show all packets on console
- `-a, --address IP` - Bind to specific IP address (default: 0.0.0.0)
- `-d, --debug` - Enable debug mode with extra connection information

### Step 2: Start the Packet Monitor Server

```bash
./packet_monitor_server [options]
```

Options:
- `-p, --port PORT` - Listen port (default: 5500)
- `-o, --output FILE` - Save packet data to file
- `-n, --no-color` - Disable colored output
- `-s, --no-stats` - Disable statistics
- `-i, --interval SEC` - Statistics display interval (default: 10)
- `-f, --forward IP:PORT` - Forward packets to external service (default: 127.0.0.1:5600)
- `--no-forward` - Disable packet forwarding
- `--connect-retry SEC` - Connection retry interval (default: 5 seconds)
- `--connect-timeout SEC` - Connection timeout (default: 3 seconds)
- `--local` - Force use of localhost (127.0.0.1) for forwarding

### Step 3: Start the Packet Agent

```bash
sudo ./packet_agent <interface> <monitor_ip> [options]
```

Arguments:
- `interface` - Network interface to monitor (e.g., eth0, wlan0)
- `monitor_ip` - IP address of the monitor server

Options:
- `-p, --port PORT` - Monitor port (default: 5500)
- `-f, --filter FILTER` - BPF packet filter
- `-l, --list` - List available network interfaces and exit

OS-specific interface examples:
- Linux: `eth0`, `wlan0`
- macOS: `en0` (WiFi), `en1` (Ethernet)
- Windows: Use the `-l` option to list available interfaces

## Packet Data Format

### Internal Protocol Formats

The system uses the following data formats for communication between components:

#### 1. Agent to Monitor Server Format

```
PACKET|<timestamp>|<src_ip>|<src_port>|<dst_ip>|<dst_port>|<protocol>|<size>
```

Fields:
- `timestamp`: ISO format timestamp (YYYY-MM-DD HH:MM:SS)
- `src_ip`: Source IP address
- `src_port`: Source port number (0 if not applicable)
- `dst_ip`: Destination IP address
- `dst_port`: Destination port number (0 if not applicable)
- `protocol`: Protocol name (HTTP, HTTPS, DNS, TCP, UDP, ICMP, etc.)
- `size`: Packet size in bytes

Example:
```
PACKET|2023-06-15 14:22:33|192.168.1.105|58234|93.184.216.34|443|HTTPS|1420
```

#### 2. Monitor Server to Receiver Service Format

```
FORWARD|<timestamp>|<src_ip>|<src_port>|<dst_ip>|<dst_port>|<protocol>|<size>|<agent_hostname>
```

Fields:
- Same as above plus `agent_hostname` which identifies the originating agent

Example:
```
FORWARD|2023-06-15 14:22:33|192.168.1.105|58234|93.184.216.34|443|HTTPS|1420|laptop-sensor1
```

### Integrating with External Services

To consume packet data from the receiver service:

1. **Direct Log File Consumption**:
   The receiver service writes packets to a log file (default: `received_packets.log`) in the following format:
   ```
   [YYYY-MM-DD HH:MM:SS] src_ip:src_port -> dst_ip:dst_port (protocol, size bytes) from hostname
   ```

2. **Custom Integration**:
   You can create your own service that listens on a port and receives forwarded data from the monitor server:
   
   - Configure the monitor server to forward to your service:
     ```
     ./packet_monitor_server -f your_service_ip:port
     ```
   
   - In your service, parse the incoming data in the format:
     ```
     FORWARD|timestamp|src_ip|src_port|dst_ip|dst_port|protocol|size|agent_hostname
     ```

3. **CSV Export**:
   The monitor server provides a feature to export packet history to CSV:
   - Start the monitor server and enter `export filename.csv` command
   - CSV format contains: Timestamp, Source IP, Source Port, Destination IP, Destination Port, Protocol, Size, Agent Hostname

## Public IP Connection Setup

We provide easy-to-use setup scripts that automatically configure and test connections using public IP addresses:

### On Linux/Unix:
```bash
# Make script executable
chmod +x public_ip_setup.sh
# Run setup tool
./public_ip_setup.sh
```

### On Windows:
```
public_ip_setup.bat
```

**What these scripts do:**
1. Detect your public IP address
2. Check if ports are available
3. Start the packet receiver service on an available port
4. Test local and public IP connections
5. Provide instructions for router port forwarding
6. Show the exact commands to run the packet monitor server and agent

This is the easiest way to set up public IP connections.

## Connection Setup Scenarios

### 1. Local Setup (Everything on the Same Machine)

This is the simplest setup and works out of the box:

```bash
# Terminal 1 - Start the receiver service
./packet_receiver_service -v

# Terminal 2 - Start the packet monitor with default settings
./packet_monitor_server

# Terminal 3 - Start the packet agent
sudo ./packet_agent eth0 127.0.0.1
```

The packet monitor will automatically connect to the receiver service on localhost.

### 2. Local Network Setup

If the packet monitor and receiver service are on different machines in the same local network:

```bash
# On Machine 1 (IP: 192.168.1.100) - Start the receiver service
./packet_receiver_service -v

# On Machine 2 - Start the packet monitor pointing to Machine 1
./packet_monitor_server -f 192.168.1.100:5600

# On Machine 2 or other machines - Start agents pointing to the monitor
sudo ./packet_agent eth0 192.168.1.101
```

### 3. Public/Remote Network Setup

For connecting across the internet using public IP addresses:

#### On the receiver side:
1. Set up port forwarding on your router: forward port 5600 to the internal IP of the machine running the receiver service
2. Allow incoming connections on port 5600 in your firewall
3. Get your public IP address: `curl ifconfig.me` or `curl checkip.amazonaws.com`
4. Start the receiver service:
   ```bash
   ./packet_receiver_service -v -d
   ```

#### On the monitor side:
```bash
./packet_monitor_server -f YOUR_PUBLIC_IP:5600 --connect-timeout 10
```

The `--connect-timeout 10` option gives more time to establish connections over the internet.

## Troubleshooting Connection Issues

If you're having trouble connecting the packet monitor server to the receiver service:

### Connection Test Tool

We provide test scripts to diagnose common connection issues:

#### On Linux/Unix:
```bash
# Make the script executable
chmod +x connection_test.sh
# Run the test
./connection_test.sh
```

#### On Windows:
```
connection_test.bat
```

The test script will:
1. Check if required components are available
2. Check if port 5600 is already in use
3. Show network interface information
4. Detect your public IP address
5. Test local connectivity
6. Check firewall status
7. Provide recommendations based on the results

### Manual Troubleshooting

1. Check if the receiver service is running
Make sure the packet_receiver_service is running and listening on the correct port.

2. Try with localhost first
Use the `--local` option to test the connection locally:
```bash
./packet_monitor_server --local
```

3. Check firewall settings
Make sure your firewall allows:
- Outgoing connections on port 5600 from the packet_monitor_server
- Incoming connections on port 5600 to the packet_receiver_service

4. Test port forwarding
If using a public IP, test if your port forwarding is working using an online port checker or:
```bash
nc -vz YOUR_PUBLIC_IP 5600
```

5. Increase connection timeout
For slow or unstable networks, increase the connection timeout:
```bash
./packet_monitor_server -f TARGET_IP:5600 --connect-timeout 10 --connect-retry 10
```

## Firewall Configuration

### Linux (UFW)
```bash
sudo ufw allow 5600/tcp
sudo ufw allow 5500/tcp
```

### macOS
```bash
# Add to pf firewall config or use System Preferences
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add $(pwd)/packet_receiver_service
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblock $(pwd)/packet_receiver_service
```

### Windows
```batch
netsh advfirewall firewall add rule name="Packet Receiver" dir=in action=allow protocol=TCP localport=5600
netsh advfirewall firewall add rule name="Packet Monitor" dir=in action=allow protocol=TCP localport=5500
```

## Data Flow

```
[Network] → [Packet Agent] → [Packet Monitor Server] → [Packet Receiver Service]
```

1. Packet Agent captures network packets
2. Agent sends packet data to Monitor Server
3. Monitor Server processes and displays packet information
4. Monitor Server automatically forwards packet data to Receiver Service
5. Receiver Service logs and processes the forwarded data

## Commands

### Monitor Server Commands

- `export [filename]` - Export packet history to CSV file
- `help` - Show help message
- `quit` - Exit the program

## Notes

- All components require appropriate permissions to create and use sockets
- The packet agent requires root/sudo privileges to capture packets
- Make sure the firewalls allow connections on the specified ports
- By default, packet forwarding is enabled to localhost (127.0.0.1:5600) 