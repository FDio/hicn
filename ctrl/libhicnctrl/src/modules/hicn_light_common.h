/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef HICNCTRL_HICN_LIGHT_COMMON
#define HICNCTRL_HICN_LIGHT_COMMON

#include <assert.h>  // assert

#include "api_private.h"

#define PORT 9695

#define BOOLSTR(x) ((x) ? "true" : "false")

/*
 * Internal state associated to a pending request
 */
typedef struct {
  int seq;
  hc_data_t *data;
  int (*parse)(const u8 *src, u8 *dst);
} hc_sock_request_t;

/**
 * Messages to the forwarder might be multiplexed thanks to the seqNum fields in
 * the header_control_message structure. The forwarder simply answers back the
 * original sequence number. We maintain a map of such sequence number to
 * outgoing queries so that replied can be demultiplexed and treated
 * appropriately.
 */
TYPEDEF_MAP_H(hc_sock_map, int, hc_sock_request_t *);

struct hc_sock_light_s {
  /* This must be the first element of the struct */
  hc_sock_t vft;

  char *url;
  int fd;

  /* Partial receive buffer */
  u8 buf[RECV_BUFLEN];
  size_t roff; /**< Read offset */
  size_t woff; /**< Write offset */

  /*
   * Because received messages are potentially unbounded in size, we might not
   * guarantee that we can store a full packet before processing it. We must
   * implement a very simple state machine remembering the current parsing
   * status in order to partially process the packet.
   */
  size_t remaining;
  u32 send_id;

  /* Next sequence number to be used for requests */
  int seq;

  /* Request being parsed (NULL if none) */
  hc_sock_request_t *cur_request;

  bool async;
  hc_sock_map_t *map;
};

typedef struct hc_sock_light_s hc_sock_light_t;

#define TO_HC_SOCK_LIGHT(s) (hc_sock_light_t *)(s)

hc_sock_request_t *hc_sock_request_create(int seq, hc_data_t *data,
                                          HC_PARSE parse);

void hc_sock_light_request_free(hc_sock_request_t *request);

/*
 * list was working with all seq set to 0, but it seems hicnLightControl uses
 * 1, and replies with the same seqno
 */
#define HICN_CTRL_SEND_SEQ_INIT 1
#define HICN_CTRL_RECV_SEQ_INIT 1

#define MAX(x, y) ((x > y) ? x : y)

static const struct in6_addr loopback_addr = IN6ADDR_LOOPBACK_INIT;

#endif /* HICNCTRL_HICN_LIGHT_COMMON */
