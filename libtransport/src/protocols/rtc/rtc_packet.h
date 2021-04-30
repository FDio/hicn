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

#pragma once
#ifndef _WIN32
#include <arpa/inet.h>
#else
#include <hicn/transport/portability/win_portability.h>
#endif

namespace transport {

namespace protocol {

namespace rtc {

inline uint64_t _ntohll(const uint64_t *input) {
  uint64_t return_val;
  uint8_t *tmp = (uint8_t *)&return_val;

  tmp[0] = (uint8_t)(*input >> 56);
  tmp[1] = (uint8_t)(*input >> 48);
  tmp[2] = (uint8_t)(*input >> 40);
  tmp[3] = (uint8_t)(*input >> 32);
  tmp[4] = (uint8_t)(*input >> 24);
  tmp[5] = (uint8_t)(*input >> 16);
  tmp[6] = (uint8_t)(*input >> 8);
  tmp[7] = (uint8_t)(*input >> 0);

  return return_val;
}

inline uint64_t _htonll(const uint64_t *input) { return (_ntohll(input)); }

const uint32_t DATA_HEADER_SIZE = 12;  // bytes
                                       // XXX: sizeof(data_packet_t) is 16
                                       // beacuse of padding
const uint32_t NACK_HEADER_SIZE = 16;

struct data_packet_t {
  uint64_t timestamp;
  uint32_t prod_rate;

  inline uint64_t getTimestamp() const { return _ntohll(&timestamp); }
  inline void setTimestamp(uint64_t time) { timestamp = _htonll(&time); }

  inline uint32_t getProductionRate() const { return ntohl(prod_rate); }
  inline void setProductionRate(uint32_t rate) { prod_rate = htonl(rate); }
};

struct nack_packet_t {
  uint64_t timestamp;
  uint32_t prod_rate;
  uint32_t prod_seg;

  inline uint64_t getTimestamp() const { return _ntohll(&timestamp); }
  inline void setTimestamp(uint64_t time) { timestamp = _htonll(&time); }

  inline uint32_t getProductionRate() const { return ntohl(prod_rate); }
  inline void setProductionRate(uint32_t rate) { prod_rate = htonl(rate); }

  inline uint32_t getProductionSegement() const { return ntohl(prod_seg); }
  inline void setProductionSegement(uint32_t seg) { prod_seg = htonl(seg); }
};

}  // end namespace rtc

}  // end namespace protocol

}  // end namespace transport