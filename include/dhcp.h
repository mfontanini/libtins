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

#ifndef __DHCP_H
#define __DHCP_H


#include <list>
#include <string>
#include "bootp.h"


namespace Tins {
    
    /** 
     * \brief Class that represents the DHCP PDU.
     * 
     * The end option is added automatically at the end of the option list.
     */
    class DHCP : public BootP {
    public:
        /** 
         * \brief DHCP flags.
         */
        enum Flags {
            DHCPDISCOVER = 1,
            DHCPOFFER    = 2,
            DHCPREQUEST	 = 3,
            DHCPDECLINE  = 4,
            DHCPACK      = 5,
            DHCPNAK      = 6,
            DHCPRELEASE	 = 7,
            DHCPINFORM   = 8
        };
        
        /** 
         * \brief DHCP options enum.
         */
        enum Options {
            PAD,
            SUBNET_MASK,
            TIME_OFFSET,
            ROUTERS,
            TIME_SERVERS,
            NAME_SERVERS,
            DOMAIN_NAME_SERVERS,
            LOG_SERVERS,
            COOKIE_SERVERS,
            LPR_SERVERS,
            IMPRESS_SERVERS,
            RESOURCE_LOCATION_SERVERS,
            HOST_NAME,
            BOOT_SIZE,
            MERIT_DUMP,
            DOMAIN_NAME,
            SWAP_SERVER,
            ROOT_PATH,
            EXTENSIONS_PATH,
            IP_FORWARDING,
            NON_LOCAL_SOURCE_ROUTING,
            POLICY_FILTER,
            MAX_DGRAM_REASSEMBLY,
            DEFAULT_IP_TTL,
            PATH_MTU_AGING_TIMEOUT,
            PATH_MTU_PLATEAU_TABLE,
            INTERFACE_MTU,
            ALL_SUBNETS_LOCAL,
            BROADCAST_ADDRESS,
            PERFORM_MASK_DISCOVERY,
            MASK_SUPPLIER,
            ROUTER_DISCOVERY,
            ROUTER_SOLICITATION_ADDRESS,
            STATIC_ROUTES,
            TRAILER_ENCAPSULATION,
            ARP_CACHE_TIMEOUT,
            IEEE802_3_ENCAPSULATION,
            DEFAULT_TCP_TTL,
            TCP_KEEPALIVE_INTERVAL,
            TCP_KEEPALIVE_GARBAGE,
            NIS_DOMAIN,
            NIS_SERVERS,
            NTP_SERVERS,
            VENDOR_ENCAPSULATED_OPTIONS,
            NETBIOS_NAME_SERVERS,
            NETBIOS_DD_SERVER,
            NETBIOS_NODE_TYPE,
            NETBIOS_SCOPE,
            FONT_SERVERS,
            X_DISPLAY_MANAGER,
            DHCP_REQUESTED_ADDRESS,
            DHCP_LEASE_TIME,
            DHCP_OPTION_OVERLOAD,
            DHCP_MESSAGE_TYPE,
            DHCP_SERVER_IDENTIFIER,
            DHCP_PARAMETER_REQUEST_LIST,
            DHCP_MESSAGE,
            DHCP_MAX_MESSAGE_SIZE,
            DHCP_RENEWAL_TIME,
            DHCP_REBINDING_TIME,
            VENDOR_CLASS_IDENTIFIER,
            DHCP_CLIENT_IDENTIFIER,
            NWIP_DOMAIN_NAME,
            NWIP_SUBOPTIONS,
            USER_CLASS = 77,
            FQDN = 81,
            DHCP_AGENT_OPTIONS = 82,
            SUBNET_SELECTION = 118,
            AUTHENTICATE = 210,
            END	= 255
        };
        
        /** 
         * \brief DHCP options struct.
         */
        struct DHCPOption {
            /** 
             * \brief The option number.
             */
            uint8_t option;
            /** 
             * \brief The value's length in bytes.
             */
            uint8_t length;
            /** 
             * \brief The option's value.
             */
            uint8_t *value;
            
            /**
             * \brief Creates an instance of DHCPOption.
             * 
             * The option's value is copied, therefore the user should
             * manually free any memory pointed by the "val" parameter.
             * \param opt The option number.
             * \param len The length of the option's value in bytes.
             * \param val The option's value.
             */
            DHCPOption(uint8_t opt, uint8_t len, const uint8_t *val);
        };
        
        /** 
         * \brief Creates an instance of DHCP.
         * 
         * This sets the hwtype and hlen fields to match the ethernet
         * type and length.
         */
        DHCP();
        
        /**
         * \brief Constructor which creates a DHCP object from a buffer and adds all identifiable
         * PDUs found in the buffer as children of this one.
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         * Subclasses might use 0 to provide their own interpretation of this field.
         */
        DHCP(const uint8_t *buffer, uint32_t total_sz);
         
        /**
         * \brief DHCP destructor
         * 
         * Releases the memory allocated for options.
         */
        ~DHCP();
        
        /** 
         * \brief Adds a new option to this DHCP PDU.
         * 
         * This copies the value buffer. Adding options may fail if
         * there's not enough size to hold a new option.
         * \param opt The option identifier.
         * \param len The length of the value field.
         * \param val The value of this option.
         * \return True if the option was added successfully.
         */
        bool add_option(Options opt, uint8_t len, const uint8_t *val);
        
        /** 
         * \brief Adds a type option the the option list.
         * \param type The type of this DHCP PDU.
         * \return True if the option was added successfully. \sa DHCP::add_option
         */
        bool add_type_option(Flags type);
        
        /** 
         * \brief Adds a server identifier option.
         * \param ip The ip of the server.
         * \return True if the option was added successfully. \sa DHCP::add_option
         */
        bool add_server_identifier(uint32_t ip);
        
        /** 
         * \brief Adds an IP address lease time option.
         * \param time The lease time.
         * \return True if the option was added successfully. \sa DHCP::add_option
         */
        bool add_lease_time(uint32_t time);
        
        /**
         * \brief Adds a subnet mask option.
         * \param mask The subnet mask.
         * \return True if the option was added successfully. \sa DHCP::add_option
         */
        bool add_subnet_mask(uint32_t mask);
        
        /** 
         * \brief Adds a routers option.
         * \param routers A list of ip addresses in integer notation.
         * \return True if the option was added successfully. \sa DHCP::add_option
         */
        bool add_routers_option(const std::list<uint32_t> &routers);
        
        /** 
         * \brief Adds a domain name servers option.
         * \param dns A list of ip addresses in integer notation.
         * \return True if the option was added successfully. \sa DHCP::add_option
         */
        bool add_dns_options(const std::list<uint32_t> &dns);
        
        /** 
         * \brief Adds a broadcast address option.
         * \param addr The broadcast address.
         * \return True if the option was added successfully. \sa DHCP::add_option
         */
        bool add_broadcast_option(uint32_t addr);
        
        /** 
         * \brief Adds a domain name option.
         * \param name The domain name.
         * \return True if the option was added successfully. \sa DHCP::add_option
         */
        bool add_domain_name(const std::string &name);
        
        /** \brief Getter for the options list.
         * \return The option list.
         */
        const std::list<DHCPOption> options() const { return _options; }
        
        /**
         * \brief Getter for the PDU's type.
         * \sa PDU::pdu_type
         */
        PDUType pdu_type() const { return PDU::UDP; }
        
        /** 
         * \brief Getter for the header size.
         * \return Returns the BOOTP header size.
         * \sa PDU::header_size
         */ 
        uint32_t header_size() const;
    private:
        static const uint32_t MAX_DHCP_SIZE;
        
        void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent);
        
        uint8_t *serialize_list(const std::list<uint32_t> &int_list, uint32_t &sz);
        
        std::list<DHCPOption> _options;
        uint32_t _size;
    };
};

#endif
