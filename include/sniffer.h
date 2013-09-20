/*
 * Copyright (c) 2012, Matias Fontanini
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
#include <iterator>
#include "pdu.h"
#include "ethernetII.h"
#include "radiotap.h"
#include "packet.h"
#include "loopback.h"
#include "dot11/dot11_base.h"
#include "dot3.h"
#include "sll.h"
#include "cxxstd.h"
#include "exceptions.h"
#include "internals.h"
#include "ppi.h"

namespace Tins {
    class SnifferIterator;

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
         * The iterator type.
         */
        typedef SnifferIterator iterator;

        #if TINS_IS_CXX11
            /**
             * \brief Move constructor.
             * This constructor is available only in C++11.
             */
            BaseSniffer(BaseSniffer &&rhs) noexcept 
            : handle(nullptr), mask()
            {
                *this = std::move(rhs);
            }
            
            /**
             * \brief Move assignment operator.
             * This operator is available only in C++11.
             */
            BaseSniffer& operator=(BaseSniffer &&rhs) noexcept 
            {
                using std::swap;
                swap(handle, rhs.handle);
                swap(mask, rhs.mask);
                return *this;
            }
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
         * The callback object must implement an operator with one of the 
         * following signatures:
         * 
         * \code
         * bool operator()(PDU&);
         * bool operator()(const PDU&);
         * \endcode
         * 
         * This operator will be called using the sniffed packets 
         * as arguments. You can modify the parameter argument as you wish. 
         * Calling PDU methods like PDU::release_inner_pdu is perfectly 
         * valid.
         * 
         * Note that the Functor object will be copied using its copy
         * constructor, so that object should be some kind of proxy to
         * another object which will process the packets(e.g. std::bind).
         *
         * Sniffing will stop when either max_packets are sniffed(if it is != 0), 
         * or when the functor returns false.
         *
         * This method catches both malformed_packet and pdu_not_found exceptions,
         * which allows writing much cleaner code, since you can call PDU::rfind_pdu
         * without worrying about catching the exception that can be thrown. This 
         * allows writing code such as the following:
         *
        * \code
         * bool callback(const PDU& pdu) {
         *     // If either RawPDU is not found, or construction of the DNS 
         *     // object fails, the BaseSniffer object will trap the exceptions, 
         *     // so we don't need to worry about it.
         *     DNS dns = pdu.rfind_pdu<RawPDU>().to<DNS>();
         *     return true;
         * }
         * \endcode
         * 
         * \param function The callback handler object which should process packets.
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
         *
         * This method must be called from the same thread from which
         * BaseSniffer::sniff_loop was called.
         */
        void stop_sniff();

        /**
         * \brief Gets the file descriptor associated with the sniffer.
         */
        int get_fd();

        /**
         * \brief Retrieves this sniffer's link type.
         *
         * This calls pcap_datalink on the stored pcap handle and
         * returns its result.
         */
        int link_type() const;

        /**
         * Retrieves an iterator to the next packet in this sniffer.
         */
        iterator begin();

        /**
         * Retrieves an end iterator.
         */
        iterator end();
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
        BaseSniffer(const BaseSniffer&);
        BaseSniffer &operator=(const BaseSniffer&);
        
        pcap_t *handle;
        bpf_u_int32 mask;
    };
    
    /** 
     * \class Sniffer
     * \brief Sniffs packets from a network interface.
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
     * \brief Reads pcap files and interprets the packets in it.
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

    /**
     * \brief Iterates over packets sniffed by a BaseSniffer.
     */
    class SnifferIterator : public std::iterator<std::forward_iterator_tag, PDU> {
    public:
        /**
         * Constructs a SnifferIterator.
         * \param sniffer The sniffer to iterate.
         */
        SnifferIterator(BaseSniffer *sniffer = 0)
        : sniffer(sniffer)
        {
            if(sniffer)
                advance();
        }

        /**
         * Advances the iterator.
         */
        SnifferIterator& operator++() {
            advance();
            return *this;
        }

        /**
         * Advances the iterator.
         */
        SnifferIterator operator++(int) {
            SnifferIterator other(*this);
            advance();
            return other;
        }

        /**
         * Dereferences the iterator.
         * \return reference to the current packet.
         */
        PDU &operator*() {
            return *pkt.pdu();
        }

        /**
         * Dereferences the iterator.
         * \return pointer to the current packet.
         */
        PDU *operator->() {
            return &(**this);
        }

        /**
         * Compares this iterator for equality.
         * \param rhs The iterator to be compared to.
         */
        bool operator==(const SnifferIterator &rhs) const {
            return sniffer == rhs.sniffer;
        }

        /**
         * Compares this iterator for in-equality.
         * \param rhs The iterator to be compared to.
         */
        bool operator!=(const SnifferIterator &rhs) const {
            return !(*this == rhs);
        }
    private:
        void advance() {
            pkt = sniffer->next_packet();
            if(!pkt)
                sniffer = 0;
        }

        BaseSniffer *sniffer;
        Packet pkt;
    };

    template<class Functor>
    void Tins::BaseSniffer::sniff_loop(Functor function, uint32_t max_packets) {
        for(iterator it = begin(); it != end(); ++it) {
            try {
                // If the functor returns false, we're done
                if(!function(*it))
                    return;
            }
            catch(malformed_packet&) { }
            catch(pdu_not_found&) { }
            if(max_packets && --max_packets == 0)
                return;
        }
    }
}
    
#endif // TINS_SNIFFER_H
