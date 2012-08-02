/*
 * libtins is a net packet wrapper library for crafting and
 * interpreting sniffed packets.
 *
 * Copyright (C) 2011 Nasel
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef TINS_CONSTANTS_H
#define TINS_CONSTANTS_H

namespace Tins {
    /**
     * \brief Constants used in protocols.
     */
    namespace Constants {
        /** \cond */
        struct IP {
        /** \endcond */
            enum e {
                PROTO_IP = 0,        /* Dummy protocol for TCP.  */
                PROTO_HOPOPTS = 0,   /* IPv6 Hop-by-Hop options.  */
                PROTO_ICMP = 1,	     /* Internet Control Message Protocol.  */
                PROTO_IGMP = 2,	     /* Internet Group Management Protocol. */
                PROTO_IPIP = 4,	     /* IPIP tunnels (older KA9Q tunnels use 94).  */
                PROTO_TCP = 6,	     /* Transmission Control Protocol.  */
                PROTO_EGP = 8,	     /* Exterior Gateway Protocol.  */
                PROTO_PUP = 12,	     /* PUP protocol.  */
                PROTO_UDP = 17,	     /* User Datagram Protocol.  */
                PROTO_IDP = 22,	     /* XNS IDP protocol.  */
                PROTO_TP = 29,	     /* SO Transport Protocol Class 4.  */
                PROTO_DCCP = 33,	 /* Datagram Congestion Control Protocol.  */
                PROTO_IPV6 = 41,     /* IPv6 header.  */
                PROTO_ROUTING = 43,  /* IPv6 routing header.  */
                PROTO_FRAGMENT = 44, /* IPv6 fragmentation header.  */
                PROTO_RSVP = 46,	 /* Reservation Protocol.  */
                PROTO_GRE = 47,	     /* General Routing Encapsulation.  */
                PROTO_ESP = 50,      /* encapsulating security payload.  */
                PROTO_AH = 51,       /* authentication header.  */
                PROTO_ICMPV6 = 58,   /* ICMPv6.  */
                PROTO_NONE = 59,     /* IPv6 no next header.  */
                PROTO_DSTOPTS = 60,  /* IPv6 destination options.  */
                PROTO_MTP = 92,	     /* Multicast Transport Protocol.  */
                PROTO_ENCAP = 98,	 /* Encapsulation Header.  */
                PROTO_PIM = 103,	 /* Protocol Independent Multicast.  */
                PROTO_COMP = 108,	 /* Compression Header Protocol.  */
                PROTO_SCTP = 132,	 /* Stream Control Transmission Protocol.  */
                PROTO_UDPLITE = 136, /* UDP-Lite protocol.  */
                PROTO_RAW = 255	     /* Raw IP packets.  */
            };
        };
        
        struct Ethernet {
            enum e {
                PUP = 0x0200,     /* Xerox PUP */
                SPRITE = 0x0500,  /* Sprite */
                IP = 0x0800,      /* IP */
                ARP = 0x0806,     /* Address resolution */
                REVARP = 0x8035,  /* Reverse ARP */
                AT = 0x809B,      /* AppleTalk protocol */
                AARP = 0x80F3,    /* AppleTalk ARP */
                VLAN = 0x8100,    /* IEEE 802.1Q VLAN tagging */
                IPX = 0x8137,	  /* IPX */
                IPV6 = 0x86dd,    /* IP protocol version 6 */
                EAPOL = 0x888e,   /* EAPOL */
                LOOPBACK = 0x9000 /* used to test interfaces */
            };
        };
        
        struct ARP {
            enum e {
                NETROM = 0,		    /* From KA9Q: NET/ROM pseudo. */
                ETHER = 1,		    /* Ethernet 10/100Mbps.  */
                EETHER = 2,		    /* Experimental Ethernet.  */
                AX25 = 3,		    /* AX.25 Level 2.  */
                PRONET = 4,		    /* PROnet token ring.  */
                CHAOS = 5,		    /* Chaosnet.  */
                IEEE802 = 6,        /* IEEE 802.2 Ethernet/TR/TB.  */
                ARCNET = 7,		    /* ARCnet.  */
                APPLETLK = 8,		/* APPLEtalk.  */
                DLCI = 15,		    /* Frame Relay DLCI.  */
                ATM	= 19,		    /* ATM.  */
                METRICOM = 23,		/* Metricom STRIP (new IANA id).  */
                IEEE1394 = 24,		/* IEEE 1394 IPv4 - RFC 2734.  */
                EUI64 = 27,		    /* EUI-64.  */
                INFINIBAND = 32,    /* InfiniBand.  */
                SLIP = 256,
                CSLIP = 257,
                SLIP6 = 258,
                CSLIP6 = 259,
                RSRVD = 260,		/* Notional KISS type.  */
                ADAPT = 264,
                ROSE	= 270,
                X25	= 271,		    /* CCITT X.25.  */
                HWX25 = 272,		/* Boards with X.25 in firmware.  */
                PPP	= 512,
                CISCO = 513,		/* Cisco HDLC.  */
                HDLC	= CISCO,
                LAPB	= 516,		/* LAPB.  */
                DDCMP = 517,		/* Digital's DDCMP.  */
                RAWHDLC = 518,		/* Raw HDLC.  */
                TUNNEL = 768,		/* IPIP tunnel.  */
                TUNNEL6 = 769,		/* IPIP6 tunnel.  */
                FRAD = 770,         /* Frame Relay Access Device.  */
                SKIP = 771,		    /* SKIP vif.  */
                LOOPBACK = 772,		/* Loopback device.  */
                LOCALTLK = 773,		/* Localtalk device.  */
                FDDI = 774,		    /* Fiber Distributed Data Interface. */
                BIF = 775,          /* AP1000 BIF.  */
                SIT = 776,		    /* sit0 device - IPv6-in-IPv4.  */
                IPDDP = 777,		/* IP-in-DDP tunnel.  */
                IPGRE = 778,		/* GRE over IP.  */
                PIMREG = 779,		/* PIMSM register interface.  */
                HIPPI = 780,		/* High Performance Parallel I'face. */
                ASH = 781,		    /* (Nexus Electronics) Ash.  */
                ECONET = 782,		/* Acorn Econet.  */
                IRDA = 783,		    /* Linux-IrDA.  */
                FCPP = 784,		    /* Point to point fibrechanel.  */
                FCAL = 785,		    /* Fibrechanel arbitrated loop.  */
                FCPL = 786,		    /* Fibrechanel public loop.  */
                FCFABRIC = 787,		/* Fibrechanel fabric.  */
                IEEE802_TR = 800,	/* Magic type ident for TR.  */
                IEEE80211 = 801,	/* IEEE 802.11.  */
                IEEE80211_PRISM = 802,	/* IEEE 802.11 + Prism2 header.  */
                IEEE80211_RADIOTAP = 803,	/* IEEE 802.11 + radiotap header.  */
                IEEE802154 = 804, /* IEEE 802.15.4 header.  */
                IEEE802154_PHY = 805, /* IEEE 802.15.4 PHY header.  */
                VOID = 0xFFFF,	     /* Void type, nothing is known.  */
                NONE = 0xFFFE,	      /* Zero header length.  */  
            };
        };
    };
};


#endif // TINS_CONSTANTS_H
