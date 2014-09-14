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


#ifndef TINS_SNIFFER_H
#define TINS_SNIFFER_H


#include <pcap.h>
#include <string>
#include <memory>
#include <stdexcept>
#include <iterator>
#include "pdu.h"
#include "packet.h"
#include "cxxstd.h"
#include "exceptions.h"
#include "internals.h"

namespace Tins {
    class SnifferIterator;
    class SnifferConfiguration;

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
            BaseSniffer(BaseSniffer &&rhs) TINS_NOEXCEPT 
            : handle(nullptr), mask()
            {
                *this = std::move(rhs);
            }
            
            /**
             * \brief Move assignment operator.
             * This operator is available only in C++11.
             */
            BaseSniffer& operator=(BaseSniffer &&rhs) TINS_NOEXCEPT 
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
         * This method returns the first valid sniffed packet that matches the 
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
         * \endcode
         * 
         * Is not, since PtrPacket can't be copy constructed. 
         * 
         * \sa Packet::release_pdu
         * 
         * \return A captured packet. If an error occured, PtrPacket::pdu 
         * will return 0. Caller takes ownership of the PDU pointer stored in 
         * the PtrPacket.
         */
        PtrPacket next_packet();
        
        /**
         * \brief Starts a sniffing loop, using a callback functor for every
         * sniffed packet.
         * 
         * The functor must implement an operator with one of the 
         * following signatures:
         * 
         * \code
         * bool(PDU&);
         * bool(const PDU&);
         * \endcode
         * 
         * This functor will be called using the each of the sniffed packets 
         * as its argument. Using PDU member functions that modify the PDU,
         * such as PDU::release_inner_pdu, is perfectly valid.
         * 
         * Note that if you're using a functor object, it will be copied using 
         * its copy constructor, so it should be some kind of proxy to
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
         * \brief Sets the read timeout for this sniffer.
         *
         * This calls pcap_set_timeout using the provided parameter.
         * \param ms The amount of milliseconds.
         */
        void set_timeout(int ms);

        /**
         * \brief Sets whether to extract RawPDUs or fully parsed packets.
         *
         * By default, packets will be parsed starting from link layer.
         * However, if you're parsing a lot of traffic, then you might
         * want to extract packets and push them into a queue, 
         * so a consumer can parse them when they're popped.
         *
         * This method allows doing that. If the parameter is true,
         * then packets taken from this BaseSniffer will only contain
         * a RawPDU which will have to entire contents of the packet.
         * 
         * \param value Whether to extract RawPDUs or not.
         */
        void set_extract_raw_pdus(bool value);

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

        void set_pcap_handle(pcap_t* const pcap_handle);

        pcap_t* get_pcap_handle();

        const pcap_t* get_pcap_handle() const;

        void set_if_mask(bpf_u_int32 if_mask);

        bpf_u_int32 get_if_mask() const;
    private:
        BaseSniffer(const BaseSniffer&);
        BaseSniffer &operator=(const BaseSniffer&);
        
        pcap_t *handle;
        bpf_u_int32 mask;
        bool extract_raw;
    };
    
    /** 
     * \class Sniffer
     * \brief Sniffs packets from a network interface.
     */
    class Sniffer : public BaseSniffer {
    public:
        /**
         * \deprecated This enum is no longer necessary. You should use the
         * Sniffer(const std::string&, const SnifferConfiguration&) constructor.
         */
        enum promisc_type {
            NON_PROMISC,
            PROMISC
        };

        /**
         * \brief Constructs an instance of Sniffer using the provided configuration.
         *
         * This constructor was added as a way to improve the parameter bloat
         * introduced by the other ones available. You should create an instance
         * of SnifferConfiguration, set the desired parameters, and then use it
         * when constructing a Sniffer object.
         *
         * \sa SnifferConfiguration
         * 
         * \param device The device which will be sniffed.
         * \param configuration The configuration object to use to setup the sniffer.
         */
        Sniffer(const std::string &device, const SnifferConfiguration& configuration);

        /**
         * \brief Constructs an instance of Sniffer.
         *
         * By default the interface won't be put into promiscuous mode, and won't
         * be put into monitor mode.
         *
         * \deprecated Use the Sniffer(const std::string&, const SnifferConfiguration&) 
         * constructor.
         * \param device The device which will be sniffed.
         * \param max_packet_size The maximum packet size to be read.
         * \param promisc bool indicating wether to put the interface in promiscuous mode.(optional)
         * \param filter A capture filter to be used on the sniffing session.(optional);
         * \param rfmon Indicates if the interface should be put in monitor mode.(optional);
         */
        Sniffer(const std::string &device, unsigned max_packet_size,
          bool promisc = false, const std::string &filter = "", bool rfmon = false);

        /**
         * \brief Constructs an instance of Sniffer.
         *
         * The maximum capture size is set to 65535. By default the interface won't
         * be put into promiscuous mode, and won't be put into monitor mode.
         *
         * \deprecated Use the Sniffer(const std::string&, const SnifferConfiguration&) 
         * constructor.
         * \param device The device which will be sniffed.
         * \param promisc Indicates if the interface should be put in promiscuous mode.
         * \param filter A capture filter to be used on the sniffing session.(optional);
         * \param rfmon Indicates if the interface should be put in monitor mode.(optional);
         */
        Sniffer(const std::string &device, promisc_type promisc = NON_PROMISC, 
          const std::string &filter = "", bool rfmon = false);

    private:
        friend class SnifferConfiguration;

        void set_snap_len(unsigned snap_len);

        void set_buffer_size(unsigned buffer_size);

        void set_promisc_mode(bool promisc_enabled);

        void set_rfmon(bool rfmon_enabled);
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
        FileSniffer(const std::string &file_name, const SnifferConfiguration& configuration);

        /**
         * \deprecated Use the constructor that takes a SnifferConfiguration instead.
         *
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

    /** 
     * \class SnifferConfiguration
     * \brief Represents the configuration of a BaseSniffer object.
     *
     * This class can be used as an easy way to configure a Sniffer 
     * or FileSniffer object.
     *
     * It can be used by constructing an object of this type, 
     * setting the desired values and then passing it to the 
     * Sniffer or FileSniffer object's constructor. This sets
     * default values for some attributes:
     *
     * - Snapshot length: 65535 bytes (64 KB).
     * - Timeout: 1000 milliseconds.
     * - Promiscuous mode: false.
     *
     * For any of the attributes not listed above, the associated
     * pcap function which is used to set them on a pcap handle
     * won't be called at all. 
     * 
     * This class can be used to configure a Sniffer object,
     * like this:
     *
     * \code
     * // Initialize the configuration.
     * SnifferConfiguration config;
     * config.set_filter("ip and port 80");
     * config.set_promisc_mode(true);
     * 
     * // Use it on a Sniffer object.
     * Sniffer sniffer("eth0", config);
     * \endcode
     */
    class SnifferConfiguration {
    public:
        /**
         * \brief The default snapshot length.
         *
         * This is 65535 by default.
         */
        static const unsigned DEFAULT_SNAP_LEN;

        /**
         * \brief The default timeout.
         *
         * This is 1000 by default.
         */
        static const unsigned DEFAULT_TIMEOUT;

        /**
         * Default constructs a SnifferConfiguration.
         */
        SnifferConfiguration();

        /**
         * Sets the snapshot length option.
         * \param snap_len The snapshot length to be set.
         */
        void set_snap_len(unsigned snap_len);

        /**
         * Sets the buffer size option.
         * \param buffer_size The buffer size to be set.
         */
        void set_buffer_size(unsigned buffer_size);

        /**
         * Sets the promiscuous mode option.
         * \param enabled The promiscuous mode value.
         */
        void set_promisc_mode(bool enabled);

        /**
         * Sets a pcap filter to use on the sniffer.
         * \param filter The pcap filter to be used.
         */
        void set_filter(const std::string& filter);

        /**
         * Sets the rfmon option.
         * \param enabled The rfmon option value.
         */
        void set_rfmon(bool enabled);

        /**
         * Sets the timeout option.
         * \param timeout The timeout to be set.
         */
        void set_timeout(unsigned timeout);
    protected:
        friend class Sniffer;
        friend class FileSniffer;

        void configure_sniffer_pre_activation(Sniffer& sniffer) const;
        void configure_sniffer_pre_activation(FileSniffer& sniffer) const;

        void configure_sniffer_post_activation(Sniffer& sniffer) const;

        unsigned _snap_len;
        bool _has_buffer_size;
        unsigned _buffer_size;
        bool _has_promisc;
        bool _promisc;
        bool _has_rfmon;
        bool _rfmon;
        bool _has_filter;
        std::string _filter;
        unsigned _timeout;
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
