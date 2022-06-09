/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
 */

/*        data packet
 *     +-----------------------------------------+
 *     | uint64_t: timestamp                     |
 *     |                                         |
 *     +-----------------------------------------+
 *     | uint32_t: prod rate (bytes per sec)     |
 *     +-----------------------------------------+
 *     | payload                                 |
 *     | ...                                     |
 */

/*        nack packet
 *     +-----------------------------------------+
 *     | uint64_t: timestamp                     |
 *     |                                         |
 *     +-----------------------------------------+
 *     | uint32_t: prod rate (bytes per sec)     |
 *     +-----------------------------------------+
 *     | uint32_t: current seg in production     |
 *     +-----------------------------------------+
 */

/*        aggregated packets
 *    +---------------------------------+
 *    |c| #pkts | len1  | len2  | ....  |
 *    +----------------------------------
 *
 *    +---------------------------------+
 *    |c| #pkts | resv  |     len 1     |
 *    +----------------------------------
 *
 *  aggregated packets header.
 *  header position. just after the data packet header
 *
 *  c: 1 bit: 0 8bit encoding, 1 16bit encoding
 *  #pkts: 7 bits: number of application packets contained
 *  8bits encoding:
 *  lenX: 8 bits: len in bites of packet X
 *  16bits econding:
 *  resv: 8 bits: reserved field (unused)
 *  lenX: 16bits: len in bytes of packet X
 */

#pragma once
#ifndef _WIN32
#include <arpa/inet.h>
#else
#include <hicn/transport/portability/win_portability.h>
#endif

#include <hicn/transport/portability/endianess.h>

#include <cstring>

namespace transport {

namespace protocol {

namespace rtc {

const uint32_t DATA_HEADER_SIZE = 12;  // bytes
                                       // XXX: sizeof(data_packet_t) is 16
                                       // beacuse of padding
const uint32_t NACK_HEADER_SIZE = 16;

struct data_packet_t {
  uint64_t timestamp;
  uint32_t prod_rate;

  inline uint64_t getTimestamp() const {
    return portability::net_to_host(timestamp);
  }
  inline void setTimestamp(uint64_t time) {
    timestamp = portability::host_to_net(time);
  }

  inline uint32_t getProductionRate() const {
    return portability::net_to_host(prod_rate);
  }
  inline void setProductionRate(uint32_t rate) {
    prod_rate = portability::host_to_net(rate);
  }
};

struct nack_packet_t {
  uint64_t timestamp;
  uint32_t prod_rate;
  uint32_t prod_seg;

  inline uint64_t getTimestamp() const {
    return portability::net_to_host(timestamp);
  }
  inline void setTimestamp(uint64_t time) {
    timestamp = portability::host_to_net(time);
  }

  inline uint32_t getProductionRate() const {
    return portability::net_to_host(prod_rate);
  }
  inline void setProductionRate(uint32_t rate) {
    prod_rate = portability::host_to_net(rate);
  }

  inline uint32_t getProductionSegment() const {
    return portability::net_to_host(prod_seg);
  }
  inline void setProductionSegment(uint32_t seg) {
    prod_seg = portability::host_to_net(seg);
  }
};

class AggrPktHeader {
 public:
  // XXX buf always point to the payload after the data header
  AggrPktHeader(uint8_t *buf, uint16_t max_packet_len, uint16_t pkt_number)
      : buf_(buf), pkt_num_(pkt_number) {
    *buf_ = 0;  // reset the first byte to correctly add the header
                // encoding and the packet number
    if (max_packet_len > 0xff) {
      setAggrPktEncoding16bit();
    } else {
      setAggrPktEncoding8bit();
    }
    setAggrPktNUmber(pkt_number);
    header_len_ = computeHeaderLen();
    memset(buf_ + 1, 0, header_len_ - 1);
  }

  // XXX buf always point to the payload after the data header
  AggrPktHeader(uint8_t *buf) : buf_(buf) {
    encoding_ = getAggrPktEncoding();
    pkt_num_ = getAggrPktNumber();
    header_len_ = computeHeaderLen();
  }

  ~AggrPktHeader(){};

  int addPacketToHeader(uint8_t index, uint16_t len) {
    if (index > pkt_num_) return -1;

    setAggrPktLen(index, len);
    return 0;
  }

  int getPointerToPacket(uint8_t index, uint8_t **pkt_ptr, uint16_t *pkt_len) {
    if (index > pkt_num_) return -1;

    uint16_t len = 0;
    for (int i = 0; i < index; i++)
      len += getAggrPktLen(i);  // sum the pkts len from 0 to index - 1

    uint16_t offset = len + header_len_;
    *pkt_ptr = buf_ + offset;
    *pkt_len = getAggrPktLen(index);
    return 0;
  }

  int getPacketOffsets(uint8_t index, uint16_t *pkt_offset, uint16_t *pkt_len) {
    if (index > pkt_num_) return -1;

    uint16_t len = 0;
    for (int i = 0; i < index; i++)
      len += getAggrPktLen(i);  // sum the pkts len from 0 to index - 1

    uint16_t offset = len + header_len_;
    *pkt_offset = offset;
    *pkt_len = getAggrPktLen(index);

    return 0;
  }

  uint8_t *getPayloadAppendPtr() { return buf_ + header_len_; }

  uint16_t getHeaderLen() { return header_len_; }

  uint8_t getNumberOfPackets() { return pkt_num_; }

 private:
  inline uint16_t computeHeaderLen() const {
    uint16_t len = 4;  // min len in bytes
    if (!encoding_) {
      while (pkt_num_ >= len) {
        len += 4;
      }
    } else {
      while (pkt_num_ * 2 >= len) {
        len += 4;
      }
    }
    return len;
  }

  inline uint8_t getAggrPktEncoding() const {
    // get the first bit of the first byte
    return (*buf_ >> 7);
  }

  inline void setAggrPktEncoding8bit() {
    // reset the first bit of the first byte
    encoding_ = 0;
    *buf_ &= 0x7f;
  }

  inline void setAggrPktEncoding16bit() {
    // set the first bit of the first byte
    encoding_ = 1;
    *buf_ ^= 0x80;
  }

  inline uint8_t getAggrPktNumber() const {
    // return the first byte with the first bit = 0
    return (*buf_ & 0x7f);
  }

  inline void setAggrPktNUmber(uint8_t val) {
    // set the val without modifying the first bit
    *buf_ &= 0x80;  // reset everithing but the first bit
    val &= 0x7f;    // reset the first bit
    *buf_ |= val;   // or the vals, done!
  }

  inline uint16_t getAggrPktLen(uint8_t pkt_index) const {
    pkt_index++;
    if (!encoding_) {  // 8 bits
      return (uint16_t) * (buf_ + pkt_index);
    } else {  // 16 bits
      uint16_t *buf_16 = (uint16_t *)buf_;
      return portability::net_to_host(*(buf_16 + pkt_index));
    }
  }

  inline void setAggrPktLen(uint8_t pkt_index, uint16_t len) {
    pkt_index++;
    if (!encoding_) {  // 8 bits
      *(buf_ + pkt_index) = (uint8_t)len;
    } else {  // 16 bits
      uint16_t *buf_16 = (uint16_t *)buf_;
      *(buf_16 + pkt_index) = portability::host_to_net(len);
    }
  }

  uint8_t *buf_;
  uint8_t encoding_;
  uint8_t pkt_num_;
  uint16_t header_len_;
};

}  // end namespace rtc

}  // end namespace protocol

}  // end namespace transport
