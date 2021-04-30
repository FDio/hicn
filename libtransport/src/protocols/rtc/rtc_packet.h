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
#endif


#ifndef htonll
#define htonll(x) ((1==htonl(1)) ? (x) : ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#endif

#ifndef ntohll
#define ntohll(x) ((1==ntohl(1)) ? (x) : ((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))
#endif


namespace transport {

namespace protocol {

namespace rtc {

// uint64_t _ntohll(const uint64_t *input) {
//   uint64_t return_val;
//   uint8_t *tmp = (uint8_t *)&return_val;

//   tmp[0] = *input >> 56;
//   tmp[1] = *input >> 48;
//   tmp[2] = *input >> 40;
//   tmp[3] = *input >> 32;
//   tmp[4] = *input >> 24;
//   tmp[5] = *input >> 16;
//   tmp[6] = *input >> 8;
//   tmp[7] = *input >> 0;

//   return return_val;
// }

// uint64_t _htonll(const uint64_t *input) { return (_ntohll(input)); }

const uint32_t DATA_HEADER_SIZE = 12;  // bytes
                                       // XXX: sizeof(data_packet_t) is 16
                                       // beacuse of padding
const uint32_t NACK_HEADER_SIZE = 16;

struct data_packet_t {
  uint64_t timestamp;
  uint32_t prod_rate;

  inline uint64_t getTimestamp() const { return ntohll(timestamp); }
  inline void setTimestamp(uint64_t time) { timestamp = htonll(time); }

  inline uint32_t getProductionRate() const { return ntohl(prod_rate); }
  inline void setProductionRate(uint32_t rate) { prod_rate = htonl(rate); }
};

struct nack_packet_t {
  uint64_t timestamp;
  uint32_t prod_rate;
  uint32_t prod_seg;

  inline uint64_t getTimestamp() const { return ntohll(timestamp); }
  inline void setTimestamp(uint64_t time) { timestamp = htonll(time); }

  inline uint32_t getProductionRate() const { return ntohl(prod_rate); }
  inline void setProductionRate(uint32_t rate) { prod_rate = htonl(rate); }

  inline uint32_t getProductionSegement() const { return ntohl(prod_seg); }
  inline void setProductionSegement(uint32_t seg) { prod_seg = htonl(seg); }
};

}  // end namespace rtc

}  // end namespace protocol

}  // end namespace transport
