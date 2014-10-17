/*
 * Copyright (c) 2014, Matias Fontanini
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

#ifndef TINS_DHCP_H
#define TINS_DHCP_H


#include <list>
#include <vector>
#include <string>
#include "bootp.h"
#include "pdu_option.h"
#include "cxxstd.h"

namespace Tins {
    /** 
     * \class DHCP
     * \brief Represents the DHCP PDU.
     *
     * This class represents a DHCP PDU. It contains helpers methods
     * which make it easy to set/get specific option values.
     * 
     * Note that when adding options, the "End" option is not added 
     * automatically, so you will have to add it yourself.
     *
     * Options can be retrieved easily from DHCP PDUs:
     *
     * \code
     * // Sniff a packet from somewhere
     * DHCP dhcp = get_dhcp_from_somewhere();
     * 
     * // This retrieves the Domain Name Servers option and converts
     * // it to a std::vector<IPv4Address>. Note that if this option
     * // is not present, an option_not_found exception is thrown.
     * for(const auto& address : dhcp.domain_name_servers()) {
     *     // address is an ip
     * }
     * 
     * \endcode
     */
    class DHCP : public BootP {
    public:
        /**
         * This PDU's flag.
         */
        static const PDU::PDUType pdu_flag = PDU::DHCP;
    
        /** 
         * DHCP flags.
         */
        enum Flags {
            DISCOVER = 1,
            OFFER    = 2,
            REQUEST	 = 3,
            DECLINE  = 4,
            ACK      = 5,
            NAK      = 6,
            RELEASE	 = 7,
            INFORM   = 8
        };
        
        /** 
         * \brief DHCP options enum.
         */
        enum OptionTypes {
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
         * The DHCP option type.
         */
        typedef PDUOption<uint8_t, DHCP> option;
        
        /**
         * The type used to store the DHCP options.
         */
        typedef std::list<option> options_type;
        
        /** 
         * \brief Creates an instance of DHCP.
         * 
         * This sets the hwtype and hlen fields to match the ethernet
         * type and length.
         */
        DHCP();
        
        /**
         * \brief Constructs a DHCP object from a buffer.
         * 
         * If there is not enough size for a BootP header, or any of
         * the TLV options contains an invalid size field, then a
         * malformed_packet exception is thrown.
         * 
         * \param buffer The buffer from which this PDU will be constructed.
         * \param total_sz The total size of the buffer.
         */
        DHCP(const uint8_t *buffer, uint32_t total_sz);
        
        /** 
         * \brief Adds a new option to this DHCP PDU.
         * \param opt The option to be added.
         */
        void add_option(const option &opt);
        
        #if TINS_IS_CXX11
            /** 
             * \brief Adds a new option to this DHCP PDU.
             * 
             * The option is move-constructed.
             * 
             * \param opt The option to be added.
             */
            void add_option(option &&opt) {
                internal_add_option(opt);
                _options.push_back(std::move(opt));
            }
        #endif 
    
        /**
         * \brief Searchs for an option that matchs the given flag.
         * \param opt_flag The flag to be searched.
         * \return A pointer to the option, or 0 if it was not found.
         */
        const option *search_option(OptionTypes opt) const;
        
        /** 
         * \brief Adds a type option to the option list.
         * 
         * The new option is appended at the end of the list.
         * 
         * \param type The type of this DHCP PDU.
         */
        void type(Flags type);
        
        /** 
         * \brief Adds an end option to the option list.
         * 
         * The new option is appended at the end of the list.
         * 
         * The END option is not added automatically. You should explicitly
         * add it at the end of the DHCP options for the PDU to be
         * standard-compliant.
         */
        void end();
        
        /** 
         * \brief Adds a server identifier option.
         * 
         * The new option is appended at the end of the list.
         * 
         * \param ip The server's IP address.
         */
        void server_identifier(ipaddress_type ip);
        
        /** 
         * \brief Adds an IP address lease time option.
         * 
         * The new option is appended at the end of the list.
         * 
         * \param time The lease time.
         */
        void lease_time(uint32_t time);
        
        /** 
         * \brief Adds a lease renewal time option.
         * 
         * The new option is appended at the end of the list.
         * 
         * \param time The lease renew time.
         */
        void renewal_time(uint32_t time);
        
        /** 
         * \brief Adds a rebind time option.
         * 
         * The new option is appended at the end of the list.
         * 
         * \param time The lease rebind time.
         */
        void rebind_time(uint32_t time);
        
        /**
         * \brief Adds a subnet mask option.
         * 
         * The new option is appended at the end of the list.
         * 
         * \param mask The subnet mask.
         */
        void subnet_mask(ipaddress_type mask);
        
        /** 
         * \brief Adds a routers option.
         * 
         * The new option is appended at the end of the list.
         * 
         * \param routers A list of ip addresses.
         */
        void routers(const std::vector<ipaddress_type> &routers);
        
        /** 
         * \brief Adds a domain name servers option.
         * 
         * The new option is appended at the end of the list.
         * 
         * \param dns A list of ip addresses.
         */
        void domain_name_servers(const std::vector<ipaddress_type> &dns);
        
        /** 
         * \brief Adds a broadcast address option.
         * 
         * The new option is appended at the end of the list.
         * 
         * \param addr The broadcast address.
         */
        void broadcast(ipaddress_type addr);
        
        /** 
         * \brief Adds a requested address option.
         * 
         * The new option is appended at the end of the list.
         * 
         * \param addr The requested address.
         */
        void requested_ip(ipaddress_type addr);
        
        /** 
         * \brief Adds a domain name option.
         * 
         * The new option is appended at the end of the list.
         * 
         * \param name The domain name.
         */
        void domain_name(const std::string &name);

        /** 
         * \brief Adds a hostname option.
         * 
         * The new option is appended at the end of the list.
         * 
         * \param name The hostname.
         */
        void hostname(const std::string &name);
        
        // Option getters
        
        /**
         * \brief Searchs for a type option.
         * 
         * If the option is not found, an option_not_found exception
         * is thrown.
         * 
         * \return uint8_t containing the type option.
         */
        uint8_t type() const;
        
        /**
         * \brief Searchs for a server identifier option.
         * 
         * If the option is not found, an option_not_found exception
         * is thrown.
         * 
         * \return ipaddress_type Containing the server identifier.
         */
        ipaddress_type server_identifier() const;
        
        /**
         * \brief Searchs for a lease time option.
         * 
         * If the option is not found, an option_not_found exception
         * is thrown.
         * 
         * \return uint32_t Containing the lease time.
         */
        uint32_t lease_time() const;
                
        /**
         * \brief Searchs for a lease renewal time option.
         * 
         * If the option is not found, an option_not_found exception
         * is thrown.
         * 
         * \return uint32_t Containing the renewal time.
         */
        uint32_t renewal_time() const;
        
        /**
         * \brief Searchs for a rebind time option.
         * 
         * If the option is not found, an option_not_found exception
         * is thrown.
         * 
         * \return uint32_t Containing the rebind time.
         */
        uint32_t rebind_time() const;
        
        /**
         * \brief Searchs for a subnet mask option.
         * 
         * If the option is not found, an option_not_found exception
         * is thrown.
         * 
         * \return ipaddress_type Containing the subnet mask.
         */
        ipaddress_type subnet_mask() const;
        
        /**
         * \brief Searchs for a routers option.
         * 
         * If the option is not found, an option_not_found exception
         * is thrown.
         * 
         * \return std::vector<ipaddress_type> Containing the routers 
         * option data.
         */
        std::vector<ipaddress_type> routers() const;
        
        /**
         * \brief Searchs for a dns option.
         * 
         * If the option is not found, an option_not_found exception
         * is thrown.
         * 
         * \return std::list<ipaddress_type> Contanining the DNS servers
         * provided.
         */
        std::vector<ipaddress_type> domain_name_servers() const; 
        
        /**
         * \brief Searchs for a broadcast option.
         * 
         * If the option is not found, an option_not_found exception
         * is thrown.
         * 
         * \return ipaddress_type Containing the broadcast address.
         */
        ipaddress_type broadcast() const;
        
        /**
         * \brief Searchs for a requested option.
         * 
         * If the option is not found, an option_not_found exception
         * is thrown.
         * 
         * \return ipaddress_type Containing the requested IP address.
         */
        ipaddress_type requested_ip() const;
        
        /**
         * \brief Searchs for a domain name option.
         * 
         * If the option is not found, an option_not_found exception
         * is thrown.
         * 
         * \return std::string Containing the domain name.
         */
        std::string domain_name() const;

        /**
         * \brief Searchs for a hostname option.
         * 
         * If the option is not found, an option_not_found exception
         * is thrown.
         * 
         * \return std::string Containing the hostname.
         */
        std::string hostname() const;
        
        /** 
         * \brief Getter for the options list.
         * \return The option list.
         */
        const options_type options() const { return _options; }
        
        /**
         * \brief Getter for the PDU's type.
         * \sa PDU::pdu_type
         */
        PDUType pdu_type() const { return pdu_flag; }
        
        /** 
         * \brief Getter for the header size.
         * \return Returns the BOOTP header size.
         * \sa PDU::header_size
         */ 
        uint32_t header_size() const;
        
        /**
         * \sa PDU::clone
         */
        DHCP *clone() const {
            return new DHCP(*this);
        }
    private:
        static const uint32_t MAX_DHCP_SIZE;
      
        void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent);

        template<class T> 
        T search_and_convert(OptionTypes opt) const {
            const option *option = search_option(opt);
            if(!option)
                throw option_not_found();
            return option->to<T>();
        }
        
        void internal_add_option(const option &opt);
        serialization_type serialize_list(const std::vector<ipaddress_type> &ip_list);
        
        options_type _options;
        uint32_t _size;
    };
}

#endif // TINS_DHCP_H
