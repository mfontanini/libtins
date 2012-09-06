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


#ifndef TINS_SNIFFER_H
#define TINS_SNIFFER_H


#include <pcap.h>
#include <string>
#include <memory>
#include <stdexcept>
#include "pdu.h"
#include "ethernetII.h"
#include "radiotap.h"

namespace Tins {
    /**
     * \class BaseSniffer
     * \brief Base class for sniffers.
     * 
     * This class implements the basic sniffing operations. Subclasses
     * should only initialize this object using a pcap_t pointer, which
     * will be used to extract packets.
     * 
     * Initialization must be done using the BaseSniffer::init method.
     */
    class BaseSniffer {
    public:
        /**
         * \brief Sniffer destructor.
         * This frees all memory used by the pcap handle.
         */
        virtual ~BaseSniffer();
        
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
         * The callback object must implement an operator with the 
         * following(or compatible) signature:
         * 
         * bool operator()(PDU*);
         * 
         * This operator will be called using the sniffed packets 
         * as arguments. The callback object <b>must not</b> delete the
         * PDU parameter. You can modify it as you wish, though. Calling
         * PDU methods like PDU::release_inner_pdu is perfectly valid.
         * 
         * Note that the Functor object will be copied using its copy
         * constructor, so that object should be some kind of proxy to
         * another object which will process the packets(e.g. std::bind).
         * 
         * \param cback_handler The callback handler object which should process packets.
         * \param max_packets The maximum amount of packets to sniff. 0 == infinite.
         */
        template<class Functor>
        void sniff_loop(Functor function, uint32_t max_packets = 0);
        
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
    protected:
        /**
         * Default constructor.
         */
        BaseSniffer();
    
        /**
         * \brief Initialices this BaseSniffer.
         * 
         * \param phandle The pcap handle to be used for sniffing.
         * \param filter The pcap filter which will be applied to the
         * stream.
         * \param if_mask The interface's subnet mask. If 0 is provided,
         * then some IP broadcast tests won't work correctly.
         */
        void init(pcap_t *phandle, const std::string &filter, bpf_u_int32 if_mask);
    private:
        template<class Functor>
        struct LoopData {
            pcap_t *handle;
            Functor c_handler;
            bool wired;
            
            LoopData(pcap_t *_handle, const Functor _handler, 
              bool is_wired) 
            : handle(_handle), c_handler(_handler), wired(is_wired) { }
        };
    
        BaseSniffer(const BaseSniffer&);
        BaseSniffer &operator=(const BaseSniffer&);
        
        bool compile_set_filter(const std::string &filter, bpf_program &prog);
        
        template<class Functor>
        static void callback_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
        
        pcap_t *handle;
        bpf_u_int32 mask;
        bpf_program actual_filter;
        bool wired;
    };
    
    /** 
     * \class Sniffer
     * \brief Sniffs packets using pcap filters.
     * 
     * This class uses a given filter to sniff packets and allow the user
     * to handle them. Each time a filter is set, it's used until a new one
     * is set. Both Sniffer::next_packet and Sniffer::sniff_loop have an
     * optional filter parameter. If a filter is set using those parameter,
     * the previously set filter is freed and the new one is used.
     */
    class Sniffer : public BaseSniffer {
    public:
        /**
         * \brief Constructs an instance of Sniffer.
         * \param device The device which will be sniffed.
         * \param max_packet_size The maximum packet size to be read.
         * \param promisc bool indicating wether to put the interface in promiscuous mode.(optional)
         * \param filter A capture filter to be used on the sniffing session.(optional);
         */
        Sniffer(const std::string &device, unsigned max_packet_size,
          bool promisc = false, const std::string &filter = "");
    };
    
    /**
     * \class FileSniffer
     * \brief Parses pcap files and interprets the packets in it.
     * 
     * This class acts exactly in the same way that Sniffer, but reads
     * packets from a pcap file instead of an interface.
     */
    class FileSniffer : public BaseSniffer {
    public:
        /**
         * \brief Constructs an instance of FileSniffer.
         * \param file_name The pcap file which will be parsed.
         * \param filter A capture filter to be used on the file.(optional);
         */
        FileSniffer(const std::string &file_name, const std::string &filter = "");
    };
        
    template<class Functor>
    void Tins::BaseSniffer::sniff_loop(Functor function, uint32_t max_packets) {
        LoopData<Functor> data(handle, function, wired);
        pcap_loop(handle, max_packets, &BaseSniffer::callback_handler<Functor>, (u_char*)&data);
    }
    
    template<class Functor>
    void Tins::BaseSniffer::callback_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
        try {
            std::auto_ptr<PDU> pdu;
            LoopData<Functor> *data = reinterpret_cast<LoopData<Functor>*>(args);
            if(data->wired)
                pdu.reset(new Tins::EthernetII((const uint8_t*)packet, header->caplen));
            else
                pdu.reset(new Tins::RadioTap((const uint8_t*)packet, header->caplen));
            bool ret_val = data->c_handler(pdu.get());
            if(!ret_val)
                pcap_breakloop(data->handle);
        }
        catch(...) {
            
        }
    }
    
    template<class T>
    class HandlerProxy {
    public:
        typedef T* ptr_type;
        typedef bool (T::*fun_type)(PDU*) ;
    
        HandlerProxy(ptr_type ptr, fun_type function) 
        : object(ptr), fun(function) {}
        
        bool operator()(PDU *pdu) {
            return (object->*fun)(pdu);
        }
    private:
        ptr_type object;
        fun_type fun;
    };
    
    template<class T>
    HandlerProxy<T> make_sniffer_handler(T *ptr, typename HandlerProxy<T>::fun_type function) 
    {
        return HandlerProxy<T>(ptr, function);
    }
};
    
#endif // TINS_SNIFFER_H
