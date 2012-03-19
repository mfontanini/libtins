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


#ifndef __SNIFFER_H
#define __SNIFFER_H


#include <pcap.h>
#include <string>
#include <stdexcept>
#include "pdu.h"

namespace Tins {
    
    /**
     * \brief Abstract sniffed packet handler.
     * 
     * Base class to handle sniffed packets when using Sniffer::sniff_loop.
     * Users should either inherit this class, or use the template class
     * SnifferHandler to provide their own handlers.
     */
    class AbstractSnifferHandler {
    public:
        /**
         * \brief AbstractSnifferHandler destructor.
         */
        virtual ~AbstractSnifferHandler() { }
        /**
         * \brief Handle a captured PDU. 
         * \return Should return false if no more sniffing is required.
         */
        virtual bool handle(PDU *pdu) = 0;
    };
    
    /** 
     * \brief Sniffer class can be used to sniff packets using filters.
     * 
     * This class uses a given filter to sniff packets and allow the user
     * to handle them. Each time a filter is set, it's used until a new one
     * is set. Both Sniffer::next_packet and Sniffer::sniff_loop have an
     * optional filter parameter. If a filter is set using those parameter,
     * the previously set filter is freed and the new one is used.
     */
    class Sniffer {
    public:
        /**
         * \brief Creates an instance of sniffer.
         * \param device The device which will be sniffed.
         * \param max_packet_size The maximum packet size to be read.
         * \param promisc bool indicating wether to put the interface in promiscuous mode.
         * \param filter A capture filter to compile and use for sniffing sessions.(optional);
         */
        Sniffer(const std::string &device, unsigned max_packet_size, bool promisc = false, const std::string &filter = "") throw(std::runtime_error);
        
        /**
         * \brief Sniffer destructor.
         * This frees all memory used by the pcap handle.
         */
        ~Sniffer();
        
        /**
         * \brief Compiles a filter and uses it to capture one packet.
         * 
         * This method returns the first sniffed packet that matches the 
         * sniffer's filter, or the first sniffed packet if no filter has
         * been set.
         * \return The captured packet, matching the given filter, 0 if an
         * error occured(probably compiling the filter).
         */
        PDU *next_packet();
        
        /**
         * \brief Starts a sniffing loop, using a callback object for every
         * sniffed packet.
         * 
         * Handlers could be user-provided classes which inherit AbstractSnifferHandler,
         * or it could be a specific SnifferHandler specialization. This method deletes
         * packets after they are handled, therefore the handlers MUST NOT delete them.
         * \param cback_handler The callback handler object which should process packets.
         * \param max_packets The maximum amount of packets to sniff. 0 == infinite.
         */
        void sniff_loop(AbstractSnifferHandler *cback_handler, uint32_t max_packets = 0);
        
        /**
         * \brief Sets a filter on this sniffer.
         * \param filter The filter to be set.
         * \return True iif it was possible to apply the filter.
         */
        bool set_filter(const std::string &filter);
        
        /**
         * \brief Stops sniffing loops.
         */
        void stop_sniff();
    private:
        bool compile_set_filter(const std::string &filter, bpf_program &prog);
        
        static void callback_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
        
        pcap_t *handle;
        bpf_u_int32 ip, mask;
        bpf_program actual_filter;
        bool wired;
    };
    
    /**
     * \brief Concrete implementation of AbstractSnifferHandler.
     * 
     * This class is instantiated using a pointer to the actual handler.
     * Every time a packet is sniffed, operator() (PDU*) will be called on
     * the given pointer. \sa AbstractSnifferHandler
     */
    template<class T> class SnifferHandler : public AbstractSnifferHandler {
    public:
        /**
         * Creates an instance of SnifferHandler.
         * \param ptr The pointer to the actual handler.
         */
        SnifferHandler(T *ptr) : handler(ptr) { }
        
        /**
         * \brief The overriden AbstractSnifferHandler::handle.
         * \param pdu The sniffed PDU.
         * \return False if no more sniffing is required, otherwise true.
         */
        bool handle(PDU *pdu) {
            return (*handler)(pdu);
        }
    private:
        T *handler;
    };
};
    
#endif
