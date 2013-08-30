AUTOMAKE_OPTIONS=subdir-objects
ACLOCAL_AMFLAGS=${ACLOCAL_FLAGS} -I m4

# pkg-config stuff
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libtins.pc

lib_LTLIBRARIES=libtins.la

libtins_la_LDFLAGS = -version-info @LIBTINS_VERSION@

AM_CXXFLAGS = -Wall -pedantic -I@LIBTINS_INCLUDE_DIR@

libtins_la_SOURCES=src/arp.cpp \
                    src/bootp.cpp \
                    src/handshake_capturer.cpp \
                    src/stp.cpp \
                    src/pppoe.cpp \
                    src/crypto.cpp \
                    src/dhcp.cpp \
                    src/dhcpv6.cpp \
                    src/dns.cpp \
                    src/dns_record.cpp \
                    src/dot3.cpp \
                    src/dot1q.cpp \
                    src/eapol.cpp \
                    src/ethernetII.cpp \
                    src/icmp.cpp \
                    src/icmpv6.cpp \
                    src/internals.cpp \
                    src/ip.cpp src/ip_address.cpp \
                    src/ipv6.cpp \
                    src/ipv6_address.cpp \
                    src/llc.cpp \
                    src/loopback.cpp \
                    src/network_interface.cpp \
                    src/packet_sender.cpp \
                    src/packet_writer.cpp \
                    src/pdu.cpp \
                    src/radiotap.cpp \
                    src/rawpdu.cpp \
                    src/rsn_information.cpp \
                    src/sll.cpp \
                    src/snap.cpp \
                    src/sniffer.cpp \
                    src/tcp.cpp \
                    src/tcp_stream.cpp \
                    src/udp.cpp \
                    src/utils.cpp \
                    src/dot11/dot11_base.cpp \
                    src/dot11/dot11_data.cpp \
                    src/dot11/dot11_mgmt.cpp \
                    src/dot11/dot11_beacon.cpp \
                    src/dot11/dot11_assoc.cpp \
                    src/dot11/dot11_auth.cpp \
                    src/dot11/dot11_probe.cpp \
                    src/dot11/dot11_control.cpp

libtinsdir = $(includedir)/tins

libtins_HEADERS = include/internals.h \
							include/dhcpv6.h \
							include/dot11.h \
							include/dot1q.h \
							include/dot3.h \
							include/small_uint.h \
							include/ip.h \
							include/dns_record.h \
							include/eapol.h \
							include/tcp_stream.h \
							include/pppoe.h \
							include/handshake_capturer.h \
							include/ipv6.h \
							include/icmpv6.h \
							include/ieee802_3.h \
							include/endianness.h \
							include/rsn_information.h \
							include/loopback.h \
							include/ethernetII.h \
							include/crypto.h \
							include/packet.h \
							include/llc.h \
							include/icmp.h \
							include/hw_address.h \
							include/packet_writer.h \
							include/macros.h \
							include/arp.h \
							include/ip_address.h \
							include/pdu.h \
							include/packet_sender.h \
							include/bootp.h \
							include/network_interface.h \
							include/sll.h \
							include/radiotap.h \
							include/dns.h \
							include/rawpdu.h \
							include/sniffer.h \
							include/snap.h \
							include/pdu_cacher.h \
							include/dhcp.h \
							include/timestamp.h \
							include/tcp.h \
							include/pdu_option.h \
							include/tins.h \
							include/udp.h \
							include/ipv6_address.h  \
							include/constants.h \
							include/utils.h \
							include/cxxstd.h \
							include/stp.h \
							include/exceptions.h \
							include/config.h \
							include/address_range.h \
							include/pdu_allocator.h

libtins_dot11_HEADERS =  include/dot11/dot11_base.h \
						include/dot11/dot11_beacon.h \
						include/dot11/dot11_data.h \
						include/dot11/dot11_mgmt.h \
						include/dot11/dot11_assoc.h \
						include/dot11/dot11_auth.h \
						include/dot11/dot11_probe.h \
						include/dot11/dot11_control.h

libtins_dot11dir  	  =     $(includedir)/tins/dot11/
