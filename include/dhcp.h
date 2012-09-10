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

#ifndef TINS_DHCP_H
#define TINS_DHCP_H


#include <list>
#include <string>
#include "bootp.h"
#include "pdu_option.h"

namespace Tins {
    class IPv4Address;
    
    /** 
     * \brief Class that represents the DHCP PDU.
     * 
     * The end option is added automatically at the end of the option list.
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
         * The DHCP option type.
         */
        typedef PDUOption<uint8_t> dhcp_option;
        
        /**
         * The type used to store the DHCP options.
         */
        typedef std::list<dhcp_option> options_type;
        
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
         * \brief Adds a new option to this DHCP PDU.
         * \param option The option to be added.
         */
        void add_option(const dhcp_option &option);
    
        /**
         * \brief Searchs for an option that matchs the given flag.
         * \param opt_flag The flag to be searched.
         * \return A pointer to the option, or 0 if it was not found.
         */
        const dhcp_option *search_option(Options opt) const;
        
        /** 
         * \brief Adds a type option the the option list.
         * \param type The type of this DHCP PDU.
         */
        void type(Flags type);
        
        /** 
         * \brief Adds an end option the the option list.
         * 
         * The END option is not added automatically. You should explicitly
         * add it at the end of the DHCP options for the PDU to be
         * standard-compliant.
         */
        void end();
        
        /** 
         * \brief Adds a server identifier option.
         * \param ip The ip of the server.
         */
        void server_identifier(ipaddress_type ip);
        
        /** 
         * \brief Adds an IP address lease time option.
         * \param time The lease time.
         */
        void lease_time(uint32_t time);
        
        /** 
         * \brief Adds a lease renewal time option.
         * \param time The lease renew time.
         */
        void renewal_time(uint32_t time);
        
        /** 
         * \brief Adds a rebind time option.
         * \param time The lease rebind time.
         */
        void rebind_time(uint32_t time);
        
        /**
         * \brief Adds a subnet mask option.
         * \param mask The subnet mask.
         */
        void subnet_mask(ipaddress_type mask);
        
        /** 
         * \brief Adds a routers option.
         * \param routers A list of ip addresses.
         */
        void routers(const std::list<ipaddress_type> &routers);
        
        /** 
         * \brief Adds a domain name servers option.
         * \param dns A list of ip addresses.
         */
        void domain_name_servers(const std::list<ipaddress_type> &dns);
        
        /** 
         * \brief Adds a broadcast address option.
         * \param addr The broadcast address.
         */
        void broadcast(ipaddress_type addr);
        
        /** 
         * \brief Adds a requested address option.
         * \param addr The requested address.
         */
        void requested_ip(ipaddress_type addr);
        
        /** 
         * \brief Adds a domain name option.
         * \param name The domain name.
         */
        void domain_name(const std::string &name);
        
        // Option getters
        
        /**
         * \brief Searchs for a type option.
         * 
         * If the option is not found, a option_not_found exception
         * is thrown.
         * 
         * \return uint8_t containing the type option.
         */
        uint8_t type() const;
        
        /**
         * \brief Searchs for a server identifier option.
         * 
         * If the option is not found, a option_not_found exception
         * is thrown.
         * 
         * \return ipaddress_type Containing the server identifier.
         */
        ipaddress_type server_identifier() const;
        
        /**
         * \brief Searchs for a lease time option.
         * 
         * If the option is not found, a option_not_found exception
         * is thrown.
         * 
         * \return uint32_t Containing the lease time.
         */
        uint32_t lease_time() const;
                
        /**
         * \brief Searchs for a lease renewal time option.
         * 
         * If the option is not found, a option_not_found exception
         * is thrown.
         * 
         * \return uint32_t Containing the renewal time.
         */
        uint32_t renewal_time() const;
        
        /**
         * \brief Searchs for a rebind time option.
         * 
         * If the option is not found, a option_not_found exception
         * is thrown.
         * 
         * \return uint32_t Containing the rebind time.
         */
        uint32_t rebind_time() const;
        
        /**
         * \brief Searchs for a subnet mask option.
         * 
         * If the option is not found, a option_not_found exception
         * is thrown.
         * 
         * \return ipaddress_type Containing the subnet mask.
         */
        ipaddress_type subnet_mask() const;
        
        /**
         * \brief Searchs for a routers option.
         * 
         * If the option is not found, a option_not_found exception
         * is thrown.
         * 
         * \return std::list<ipaddress_type> Containing the routers 
         * option data.
         */
        std::list<ipaddress_type> routers() const;
        
        /**
         * \brief Searchs for a dns option.
         * 
         * If the option is not found, a option_not_found exception
         * is thrown.
         * 
         * \return std::list<ipaddress_type> Contanining the DNS servers
         * provided.
         */
        std::list<ipaddress_type> domain_name_servers() const; 
        
        /**
         * \brief Searchs for a broadcast option.
         * 
         * If the option is not found, a option_not_found exception
         * is thrown.
         * 
         * \return ipaddress_type Containing the broadcast address.
         */
        ipaddress_type broadcast() const;
        
        /**
         * \brief Searchs for a requested option.
         * 
         * If the option is not found, a option_not_found exception
         * is thrown.
         * 
         * \return ipaddress_type Containing the requested IP address.
         */
        ipaddress_type requested_ip() const;
        
        /**
         * \brief Searchs for a domain name option.
         * 
         * If the option is not found, a option_not_found exception
         * is thrown.
         * 
         * \return std::string Containing the domain name.
         */
        std::string domain_name() const;
        
        /** \brief Getter for the options list.
         * \return The option list.
         */
        const options_type options() const { return _options; }
        
        /**
         * \brief Getter for the PDU's type.
         * \sa PDU::pdu_type
         */
        PDUType pdu_type() const { return PDU::DHCP; }
        
        /** 
         * \brief Getter for the header size.
         * \return Returns the BOOTP header size.
         * \sa PDU::header_size
         */ 
        uint32_t header_size() const;
        
        /**
         * \sa PDU::clone_pdu
         */
        DHCP *clone_pdu() const {
            return new DHCP(*this);
        }
    private:
        static const uint32_t MAX_DHCP_SIZE;
        
        template<typename T>
        struct type2type {};
      
        void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent);
        
        template<class T> 
        T generic_search(Options opt, type2type<T>) const {
            const dhcp_option *option = search_option(opt);
            if(option && option->data_size() == sizeof(T))
                return *(const T*)option->data_ptr();
            else
                throw option_not_found();
        }
        
        std::list<ipaddress_type> generic_search(Options opt, type2type<std::list<ipaddress_type> >) const;
        std::string generic_search(Options opt, type2type<std::string>) const;
        ipaddress_type generic_search(Options opt, type2type<ipaddress_type>) const;
        
        serialization_type serialize_list(const std::list<ipaddress_type> &ip_list);
        
        options_type _options;
        uint32_t _size;
    };
};

#endif // TINS_DHCP_H
