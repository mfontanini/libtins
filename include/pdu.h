#ifndef __PDU_H
#define __PDU_H


#include <stdint.h>

class PDU {
public:
    PDU(uint32_t pdu_flag, PDU *next_pdu = 0);
    virtual ~PDU();
    
    /* This PDU's header size only. */
    virtual uint32_t header_size() const = 0;
    /* This PDU's trailer size only. Defaults to 0. */
    virtual uint32_t trailer_size() const { return 0; }
    
    /* The size of the whole chain of PDUs, including this one. */
    uint32_t size() const;
    
    inline const PDU *inner_pdu() const { return _inner_pdu; }
    
    /* When setting a new inner_pdu, the instance takes
     * ownership of the object, therefore deleting it when
     * it's no longer required. */
    void inner_pdu(PDU *next_pdu);
    
    /* Serializes the whole chain of PDU's, including this one. */
    uint8_t *serialize();
    
    /* Serialize this PDU storing the result in buffer. */
    void serialize(uint8_t *buffer, uint32_t total_sz);
protected:
    /* Each PDU's own implementation of serialization. */
    virtual void write_serialization(uint8_t *buffer, uint32_t total_sz) = 0;
private:
    uint32_t _pdu_flag;
    PDU *_inner_pdu;
};

#endif
