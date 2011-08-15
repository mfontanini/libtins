#ifndef __ICMP_H
#define __ICMP_H


#include "pdu.h"

namespace Tins {
    
    /** \brief ICMP represents the ICMP PDU.
     * 
     * ICMP is the representation of the ICMP PDU. Instances of this class
     * must be sent over a level 3 PDU, this will otherwise fail.
     */
    class ICMP : public PDU {
    public:
        /** \brief ICMP flags
         */ 
        enum Flags {
            ECHO_REPLY       = 0,
            DEST_UNREACHABLE = 3,
            SOURCE_QUENCH    = 4,
            REDIRECT         = 5,
            ECHO_REQUEST     = 8,
            TIME_EXCEEDED    = 11,
            PARAM_PROBLEM    = 12,
            INFO_REQUEST     = 15,
            INFO_REPLY       = 16
        }; 
    
        /** \brief Creates an instance of ICMP.
         * 
         * If no flag is specified, then ECHO_REPLY will be used.
         * \param flag The type flag which will be set.
         */
        ICMP(Flags flag = ECHO_REPLY);
        
        /** \brief Sets the code field.
         * 
         * \param new_code The code which will be stored in the ICMP struct.
         */
        void code(uint8_t new_code);
        
        /** \brief Sets the type field.
         * 
         * \param new_code The type which will be stored in the ICMP struct.
         */
        void type(uint8_t type);
        
        /** \brief Sets echo request flag for this PDU.
         * 
         * \param id The identifier for this request.
         * \param seq The sequence number for this request.
         */
        void set_echo_request(uint16_t id, uint16_t seq);
        
        /** \brief Sets echo request flag for this PDU.
         * 
         * This uses a global id and sequence number to fill the request's
         * fields. 
         */
        void set_echo_request();
        
        /** \brief Sets echo reply flag for this PDU.
         * 
         * \param id The identifier for this request.
         * \param seq The sequence number for this request.
         */
        void set_echo_reply(uint16_t id, uint16_t seq);
        
        /** \brief Sets echo reply flag for this PDU.
         * 
         * This uses a global id and sequence number to fill the request's
         * fields. 
         */
        void set_echo_reply();
        
        /** \brief Sets information request flag for this PDU.
         * 
         * \param id The identifier for this request.
         * \param seq The sequence number for this request.
         */
        void set_info_request(uint16_t id, uint16_t seq);
        
        /** \brief Sets information reply flag for this PDU.
         * 
         * \param id The identifier for this request.
         * \param seq The sequence number for this request.
         */
        void set_info_reply(uint16_t id, uint16_t seq);
        
        /** \brief Sets destination unreachable for this PDU.
         */
        void set_dest_unreachable();
        
        /** \brief Sets time exceeded flag for this PDU.
         * 
         * \param ttl_exceeded If true this PDU will represent a ICMP ttl 
         * exceeded, otherwise it will represent a fragment reassembly 
         * time exceeded.
         */
        void set_time_exceeded(bool ttl_exceeded = true);
        
        /** \brief Sets parameter problem flag for this PDU.
         * 
         * \param set_pointer Indicates wether a pointer to the bad octet
         * is provided.
         * \param bad_octet Identifies the octet in which the error was
         * detected. If set_pointer == false, it is ignored.
         */
        void set_param_problem(bool set_pointer = false, uint8_t bad_octet = 0);
        
        /** \brief Sets source quench flag for this PDU.
         */
        void set_source_quench();
        
        /** \brief Sets redirect flag for this PDU.
         * 
         * \param icode The code to be set.
         * \param address Address of the gateway to which traffic should
         * be sent.
         */
        void set_redirect(uint8_t icode, uint32_t address);
        
        /** \brief Returns the ICMP type flag.
         */
        Flags type() const { return (Flags)_icmp.type; }
        
        /** \brief Returns the ICMP code flag.
         */
        uint8_t code() const { return _icmp.code; }
        
        /** \brief Returns the header size.
         * 
         * This metod overrides PDU::header_size. This size includes the
         * payload and options size. \sa PDU::header_size
         */
        uint32_t header_size() const;
        
        bool matches_response(uint8_t *ptr, uint32_t total_sz);
        
        PDU *clone_packet(uint8_t *ptr, uint32_t total_sz);
    private:
        static uint16_t global_id, global_seq;
    
        struct icmphdr {
            uint8_t	type;
            uint8_t	code;
            uint16_t check;
            union {
                struct {
                    uint16_t id;
                    uint16_t sequence;
                } echo;
                uint32_t gateway;
                struct {
                    uint16_t __unused;
                    uint16_t mtu;
                } frag;
            } un;
        } __attribute__((packed));
        
        /** \brief Creates an instance of ICMP from a icmphdr pointer.
         * 
         * \param ptr The icmphdr to clone.
         */
        ICMP(icmphdr *ptr);
        
        /** \brief Serialices this ICMP PDU.
         * \param buffer The buffer in which the PDU will be serialized.
         * \param total_sz The size available in the buffer.
         * \param parent The PDU that's one level below this one on the stack.
         */
        void write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent);
        
        icmphdr _icmp;
    };
};

#endif
