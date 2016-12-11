##### v3.4 - Wed Mar  9 20:24:54 PST 2016

- Check the secure bit on HandshakeCapturer to detect 2nd packet

- Add info members directly into NetworkInterface

- Add IPv6 addresses to NetworkInterface::Info

- Make *MemoryStream use size_t rather than uint32_t

- Add WPA2Decrypter callback interface

- Set MACOSX_RPATH to ON

- Don't fail configuration if openssl is missing

- Build layer 5 as RawPDU if IPv6 has fragment header

- Fix examples so they build on gcc 4.6

- Fix flag value for sniffer's immediate mode

- Fix IP fragment reassemble when packet has flags DF+MF

- Add extract_metadata to main PDU classes

- Fix examples to make them work on Windows

- Use timercmp/sub and std::chrono to subtract timevals on PacketSender

- Build examples against local libtins build

- Add uninstall target

- Prefix HAVE_ config.h macros with TINS_

- Use compiler intrinsics to swap bytes

- Use C++11 mode by default

- Add missing TINS_API to PDU classes.

- Extend/fix ICMPv6 enum values and unify naming

- Return an empty string for dot11 ssid, if ssid is present but empty

- Implement new TCP stream follower mechanism

- Use ExternalProject_Add rather than including the gtest directory

- Fix invalid endian on IP fragment offset on OSX

##### v3.3 - Sun Jan 31 21:06:04 PST 2016

- Add TCP connection close example

- Move implementations on utils.h to utils.cpp

- Add ICMPv6 Multicast Listener Query Messages support 

- Add ICMPv6 Multicast Listener Report Message support

- Make DNS::Query and DNS::Resource lowercase and deprecate the old names

- Change DNS::query/resource::type to query_type and deprecate old name

- Add DNS Start Of Authority parsing and serialization

- Parse and serialize MX preference field correctly

- Add NetworkInterface::friendly_name to get Windows friendly names

- Mask 16 bits on random number generated on traceroute example

- Fix TCP sequence number addition/subtraction when wrapping around

- Use 802.1ad protocol flag when seralizing stacked Dot1Q

- Code cleanup and use same syntax on the entire project

- Correctly serialize PPPoE session packets

- Fix IPv6 extension headers parsing/serialization

- Include examples before src to avoid duplicate tins target issue

- Add MPLS PDU and hook it up with ICMP extensions

- Set UDP checksum to 0xffff if it's 0

- Don't define TINS_STATIC in config.h

- Fix invalid RSNEAPOL parsing issue

- Remove special clang on OSX case when building gtest

- Update pseudoheader_checksum signature

- Fix overall checksum calculation

- Set ICMP payload length without padding if no extensions are present

- Export classes on Windows shared lib builds

- Use google/googletest submodule and update to HEAD

- Remove unused cassert header inclusions

- Add input/output memory stream classes port PDU classes to use them

- Add extensions for ICMP/ICMPv6

- Fix RSNInformation issues on big endian architectures

- Add IP::fragment_offset and IP::flags

- Don't set Ethernet type if inner PDU type is unknown

- Don't run IP source address overwrite tests on OSX

- Always calculate IP/IPv6 checksum

- Fix invalid constant value on PPPoE

- Define default constructor for PKTAP

- Guard 802.11 parsing code on PPI around HAVE_DOT11

- Fix parsing of Dot11 packets encapsulated on PPI having FCS-at-end

- Fix DataLinkType typo on doxygen docs

- Update docs on sniff_loop handle persistency

- Use uint32_t for DNS resource TTL setter

- Erase streams when they're reassembed on IPv4Reassembler

- Make all exceptions derive from exception_base

- Add remove_option member to IP, TCP, Dot11, ICMPv6, DHCP and DHCPv6

- Allow HW addresses to be 00:00:00:00:00 on NetworkInterface::info

- Increment option size when adding a new DHCPv6 option

- Use NOMINMAX on examples

- Add metric field to RouteEntry

- Allow setting immediate mode on Sniffer

- Use one flags field for all flags on SnifferConfiguration

- Add ICMP responses example

- Add interfaces_info example

- Fix bug on SessionKeys::SessionKeys

- Fix compilation errors on android platform

- Fix example compilation on Windows

- Add PacketWriter::write overload that takes a Packet

- Use different IP addresses on IP tests depending on OS

- Allow retrieving keys on WPA2Decrypter

- Add NetworkInterface::is_up and NetworkInterface::info

- Add NetworkInterface::Info::is_up

- Fix compilation warnings on Windows x64

- Fix FindPCAP.cmake to find winpcap on x64

- Fix more tests warnings triggered on Windows

- Fix tests compilation warnings on Windows

- Fix error on VC triggered by pcap redefining the "inline" keyword

- Soften DNS parsing rules

- Replace WIN32 macro with _WIN32

- Fix IPv6Address::to_string on Windows

- Fix DNS issues triggered on VC

- Add google test as git submodule

- Perserve IP protocol when using RawPDU

- Use pcap_sendpacket by default to send packets on Windows

- Don't allow receiving l2 packets on windows

- Added RadioTap channel map type

- Made rsn_information() a const member function to make Dot11ManagementFrame 
immutable

- Ensure HAVE_CXX11 is checked when defining TINS_IS_CXX11

- Use one integer field for all flags on TCP

- Fix invalid DNS IPv4 address parsing on big endian arch

- Don't compile WPA2 test if LIBTINS_ENABLE_WPA2=0

- Add Dot11 radio measurement name corresponding to IEEE 802.11-2012

-------------------------------------------------------------------------------

##### v3.2 - Fri Mar 20 22:12:23 PST 2015

- Added include guard for config.h.

- The functor used on BaseSniffer::sniff_loop can now take a Packet.

- Added mcs, tx_flags, ext and data_retries options to RadioTap.

- Fixed big endian representation of RadioTap header.

- RadioTap's dbm_signal and dbm_noise are now signed.

- RadioTap now throws if an option is not present when getting
its value.

- TKIP decryption now works correctly on packets from AP to STA.

- Added support for PKTAP header.

- Fixed endian issue on IPv4Address::ip_to_int on Windows.

- Fixed IP parsing when total length is 0 due to TCP segmentation offload.

- Re-added support for pkg-config.

- TCPStreamFollower now calls PDU::find_pdu instead of PDU::rfind_pdu.

- Fixed assertion throw caused by DNS parsing on Windows on debug mode.

- Added throw on BSD when trying to send_recv L3 packets.

- Added Loopback::matches_response.

- Removed obsolete autotools files.

- Fixed exception thrown when an interface didn't have an IP address 
on NetworkInterface.

- Added NetworkInterface::is_loopback.

- Moved all headers to the directory include/tins.

- Fixed compilation warning on TCPStramFollower due to signed to unsigned
conversion on integral constant.

- BaseSniffer::get_pcap_handle is now public.

- PPPoE session packets are now parsed correctly.

- Fixed invalid Loopback protocol detection on FreeBSD/OSX.

- Fixed OSX IP packet sending issue.

- Added useful constructors to RawPDU.

- Fixed compilation errors on FreeBSD.

- Improved documentation on several classes.

- Fixed parsing bug when allocating IP over IP packets.

- Fixed Windows network interface naming.

- Utils::network_interface returns pcap compatible names on Windows.

- NetworkInterface::name now works on Windows.

- Added documentation generation through the build system.

- Added SnifferConfiguration class.

- Fixed bug on Dot3 serialization.

- Added OfflinePacketFilter class.

- Renamed NOEXCEPT macro to TINS_NOEXCEPT.

- Added DataLinkType class.

- IPv4Address now uses inet_pton when constructing from string. 

-------------------------------------------------------------------------------

##### v3.1 - Sun Aug 24 21:39:43 ART 2014

- Fixed ICMPv6 checksum error on serialization.

- Fixed empty domain name encoding on DNS.

- Changed the build system to CMake.

-------------------------------------------------------------------------------

##### v3.0 - Thu Aug  7 21:39:09 ART 2014

- Timestamps can now be constructed from std::chrono::duration.

- Packets can now be constructed from a PDU pointer and take ownership
of it.

- All protocols now set the next layer protocol flag, regardless if 
it was already set. This was not done in some protocols, 
like EthernetII, and as a consequence if the network layer protocol
was replaced by other, the packet would be serialized incorrectly.

- Fixed invalid parsing of some unknown DNS records.

- Fixed unaligned memory accesses that were not supported under
ARMv4 and ARMv5.

- Added BaseSniffer::set_extract_raw_pdus.

- Reduced minimum automake version to 1.11.

- Added Utils::to_string(PDU::PDUType).

- Fixed error compilations on Windows.

- Fixed ICMPv6 checksum calculation.

- Added method in IP and TCP to emplace an option (C++11 only).

- Added small option optimization to PDUOption.

- Fixed error compilation on RSNInformation.

- Renamed ICMP::check to ICMP::checksum.

- Added Sniffer support to set interface to promiscuous mode.

- TCPStreamFollower now handles overlapping fragments correctly.

- Fixed bugs in TCPStreamFollower which didn't allow it to follow
stream correctly.

- TCPStreamFollower now doesn't clear its state after every call to
TCPStreamFollower::follow_streams.

- Added IPv6 flag check to pdu_flag_to_ip_type.

- Added DHCP::hostname to extract the hostname options.

- Removed extra qualifier on SessionKeys::decrypt_unicast which 
produced compilation errors on some platforms.

- PacketSender::send now uses PDU::matches_flag to match specific
PDU types.

- Removed 'no newline at end of file' warnings.

- Fixed bug when calling BIOCIMMEDIATE on *BSD.

- Fixed bug on PacketSender::send_recv which didn't work under *BSD.

- Fixed bug triggered by not including the string header.

-------------------------------------------------------------------------------

##### v2.0 - Thu Jan 23 11:09:38 ART 2014 

- DNSResourceRecord was removed. Now DNS records are added using 
DNS::Resource.

- tins.h now includes ppi.h.

- Done significant improvements in the speed of DNS parsing.

- Added PDUOption<>::to<> which converts a PDUOption to a specific type.

- Layer 3 packets sent using PacketSender::send_recv for which the 
answer is a different PDU type.

- ICMP::gateway now uses IPv4Address.

- Added support for ICMP address mask request/reply.

- Fixed bug in PacketSender when using send_recv and a layer 2 PDU. The 
interface in which the packet was sent was not the default_interface 
set when the sender was constructed.

- IP packets sent using PacketSender::send_recv now match ICMP 
responses.

- Added support for ICMP timestamp request/reply packets. 
ICMP::matches_response now works with these types of packets as well.

- Added support for reassembling of fragmented IP packets via the
IPv4Reassembler class.

- Fragmented IP packet's inner_pdu PDUs are not decoded now.

- Added 1000ms as the default read timeout used when calling 
pcap_open_live. Added BaseSniffer::set_timeout to modify this parameter.

- Added the --disable-dot11 configure switch.

- Added support for IPSec.

- Fixed bug triggered when ifaddrs::ifa_addr was null in 
NetworkInterface::addresses.

- Added another overload of Utils::route_entries which returns the
result either than storing it in a parameter.

- Added ARP monitor, WPS detector, DNS queries sniffer and DNS spoofer 
examples.

- Added another Sniffer constructor which doesn't expect the maximum
capture size.

- Added tins_cast as a replacement for dynamic_cast on PDUs.

-------------------------------------------------------------------------------

##### v1.2 - Mon oct  7 23:33:49 ART 2013

- Added BaseSniffer::begin and BaseSniffer::end.

- BaseSniffer::next_packet uses pcap_loop instead of pcap_next, which
doesn't work well on some linux distributions.

- Added PPI PDU class.

- Fixed a bug in EthernetII triggered when the size of the whole frame 
was lower than 60 bytes.

- Added AddressRange class and IPv4Address, IPv6Address and 
HWAddress<>::operator/.

- Added is_broadcast, is_multicast and is_unicast to IPv4, IPv6
and HWAddress.

- Added is_private and is_loopback methods to IPv4 and IPv6 addresses.

- Done some optimizations on TCP's constructor from buffer.

- Added helper functions to Dot11Data to retrieve the source, 
destination and BSSID addresses.

- Fixed bugs in DNS triggered when parsing MX and unknown records.

- BaseSniffer::next_packet now iterates until a valid packet is found.

- TCP::get_flag is now const.

- The --disable-wpa2 now works as expected.

v1.1 - Wed Jun  5 09:03:37 ART 2013

- Implemented std::hash specialization for IPv4, IPv6 and HWAddress<>
types.

- Added a RSNHandshakeCapturer class.

- Added WPA2Decrypter class.

- IEEE 802.11 frames are not parsed if the RadioTap FAILED_FCS flag 
is on.

- RadioTap now calculates its size everytime it's serialized.

- Splitted the dot11.h and dot11.cpp files into several files to
speed up compilation times.

- Added HWAddress<>::is_broadcast and HWAddress::operator[].

- Fixed a bug triggered when parsing Dot11QoSData frames.

v1.0 - Tue Apr 23 20:40:57 ART 2013

- Link layer protocol PDUs now don't hold a NetworkInterface. This led
to changes in their constructors.

- Removed the obsolete PDU* parameter taken by several classes' 
constructors.

- IP now sets the sender's address automatically when no link layer
PDU is used.

- IP, TCP and UDP now calculate the checksum everytime they're 
serialized.

- Added PDU::rfind_pdu.

- Defined several exception types.

- Implemented matches_response on several protocols.

- PacketSender is now movable.

- Added an overload of add_option that takes an rvalue-reference in IP, 
TCP, DHCP, ICMPv6 and Dot11.

- Added support for GNU/kFreeBSD.

- Removed several deprecated methods, such as PDU::clone_packet.

- Added PacketSender::send(PDU&, NetworkInterface).

- Normalized the TLV options naming conventions in all of the classes
that used them.

- Added support for Dot1Q, STP, PPPoE protocols.

- Made some important optimizations on PDUOption<>'s constructors.

- Added Utils::resolve_domain and Utils::resolve_domain6

-------------------------------------------------------------------------------

##### v0.3 - Thu Jan 31 16:47:27 ART 2013

- Added IPv6, ICMPv6 and DHCPv6 classes.

- Added support for Loopback interfaces and the Linux Crooked Capture
pseudo protocol.

- Added support for IPv6 records in DNS.

- Added Packet/RefPacket class.

- Added support for FreeBSD, OSX and Windows.

- Added C++11 move semantics to several classes.

- Done a complete rewrite of the build system; it now uses libtool.

- Fixed several bugs in DNS.

-------------------------------------------------------------------------------

##### v0.2 - Sat Oct 20 11:26:40 2012

- Added support for big endian architectures. 

- Simplified several interfaces.

- Added IPv4Address and HWAddress class to simplify handling IP and hardware addresses.

- Added NetworkInterface class to abstract network interfaces.

- Added TCPStreamFollower class to follow TCP streams on the fly.

- Added WEPDecrypter class to decrypt WEP-encrypted 802.11 data frames on the fly.

- Added several new PDUs: Loopback, IEEE802_3, LLC, DNS.

- Added support for reading and writing pcap files.

- Moved to BSD-2 license.
