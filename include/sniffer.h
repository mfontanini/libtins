/*
 * Copyright (c) 2012, Nasel
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


#ifndef TINS_SNIFFER_H
#define TINS_SNIFFER_H


#include <pcap.h>
#include <string>
#include <memory>
#include <stdexcept>
#include "pdu.h"
#include "ethernetII.h"
#include "radiotap.h"
#include "packet.h"
#include "loopback.h"
#include "dot11.h"
#include "sll.h"
#include "cxxstd.h"
#include "exceptions.h"

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
        #if TINS_IS_CXX11
            /**
             * \brief Move constructor.
             * This constructor is available only in C++11.
             */
            BaseSniffer(BaseSniffer &&rhs) noexcept;
            
            /**
             * \brief Move assignment operator.
             * This opeartor is available only in C++11.
             */
            BaseSniffer& operator=(BaseSniffer &&rhs) noexcept;
        #endif
    
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
         * 
         * The return type is a thin wrapper over a PDU* and a Timestamp
         * object. This wrapper can be both implicitly converted to a 
         * PDU* and a Packet object. So doing this:
         * 
         * \code
         * Sniffer s(...);
         * std::unique_ptr<PDU> pdu(s.next_packet());
         * // Packet takes care of the PDU*. 
         * Packet packet(s.next_packet());
         * \endcode
         * 
         * Is fine, but this:
         * 
         * \code
         * // bad!!
         * PtrPacket p = s.next_packet();
         * 
         * \endcode
         * 
         * Is not, since PtrPacket can't be copy constructed. 
         * 
         * \sa Packet::release_pdu
         * 
         * \return The captured packet, matching the given filter.
         * If an error occured(probably compiling the filter), PtrPacket::pdu
         * will return 0. Caller takes ownership of the PDU * stored in
         * the PtrPacket.
         */
        PtrPacket next_packet();
        
        /**
         * \brief Starts a sniffing loop, using a callback object for every
         * sniffed packet.
         * 
         * The callback object must implement an operator with some of
         * the following(or compatible) signatures:
         * 
         * \code
         * bool operator()(PDU&);
         * bool operator()(RefPacket&);
         * \endcode
         * 
         * This operator will be called using the sniffed packets 
         * as arguments. You can modify the parameter argument as you wish. 
         * Calling PDU methods like PDU::release_inner_pdu is perfectly 
         * valid.
         * 
         * The callback taking a RefPacket will contain a timestamp
         * indicating the moment in which the packet was taken out of 
         * the wire/pcap file. 
         * 
         * Note that the Functor object will be copied using its copy
         * constructor, so that object should be some kind of proxy to
         * another object which will process the packets(e.g. std::bind).
         * 
         * \sa RefPacket
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

        /**
         * \brief Gets the file descriptor associated with the sniffer.
         */
        int get_fd();
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
            int iface_type;
            
            LoopData(pcap_t *_handle, const Functor _handler, 
              int if_type) 
            : handle(_handle), c_handler(_handler), iface_type(if_type)
            { }
        };
    
        BaseSniffer(const BaseSniffer&);
        BaseSniffer &operator=(const BaseSniffer&);
        
        template<class ConcretePDU, class Functor>
        static bool call_functor(LoopData<Functor> *data, const u_char *packet, const struct pcap_pkthdr *header);
        
        bool compile_set_filter(const std::string &filter, bpf_program &prog);
        
        template<class Functor>
        static void callback_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
        
        pcap_t *handle;
        bpf_u_int32 mask;
        bpf_program actual_filter;
        int iface_type;
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
        LoopData<Functor> data(handle, function, iface_type);
        pcap_loop(handle, max_packets, &BaseSniffer::callback_handler<Functor>, (u_char*)&data);
    }
    
    template<class ConcretePDU, class Functor>
    bool Tins::BaseSniffer::call_functor(LoopData<Functor> *data, const u_char *packet, 
      const struct pcap_pkthdr *header) 
    {
        ConcretePDU some_pdu((const uint8_t*)packet, header->caplen);
        Timestamp ts(header->ts);
        RefPacket pck(some_pdu, ts);
        return data->c_handler(pck);
    }
    
    template<class Functor>
    void Tins::BaseSniffer::callback_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
        bool ret_val(false);
        LoopData<Functor> *data = reinterpret_cast<LoopData<Functor>*>(args);
        try {
            std::auto_ptr<PDU> pdu;
            if(data->iface_type == DLT_EN10MB)
                ret_val = call_functor<Tins::EthernetII>(data, packet, header);
            else if(data->iface_type == DLT_IEEE802_11_RADIO)
                ret_val = call_functor<Tins::RadioTap>(data, packet, header);
            else if(data->iface_type == DLT_IEEE802_11) {
                std::auto_ptr<PDU> pdu(Tins::Dot11::from_bytes((const uint8_t*)packet, header->caplen));
                if(pdu.get()) {
                    RefPacket pck(*pdu, header->ts);
                    ret_val = data->c_handler(pck);
                }
            }
            else if(data->iface_type == DLT_NULL) 
                ret_val = call_functor<Tins::Loopback>(data, packet, header);
            else if(data->iface_type == DLT_LINUX_SLL)
                ret_val = call_functor<Tins::SLL>(data, packet, header);
        }
        catch(malformed_packet&) {
            
        }
        if(!ret_val)
            pcap_breakloop(data->handle);
    }
    
    template<class T>
    class HandlerProxy {
    public:
        typedef T* ptr_type;
        typedef bool (T::*fun_type)(PDU&) ;
    
        HandlerProxy(ptr_type ptr, fun_type function) 
        : object(ptr), fun(function) {}
        
        bool operator()(PDU &pdu) {
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
}
    
#endif // TINS_SNIFFER_H
