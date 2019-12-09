/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
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

#ifndef wldr_h
#define wldr_h

#include <hicn/hicn-light/config.h>
#include <hicn/core/connection.h>
#include <hicn/core/message.h>

#define BUFFER_SIZE 8192
#define MAX_RTX 3
#define WLDR_LBL 13
#define WLDR_NOTIFICATION 14
#define WLDR_UNKNOWN 15

//  NORMAL PACKET or RETRASMISSION
//      WLDR_LBL:  label = window size in the TCP header
//  NOTIFICATION
//    WLDR_NOTIFICATION:  expected_label = window size in the TCP header,
//    last_received_label = urgent pointer in the TCP header
//                        ATTENTION!!! in order to detect a notificaiton the
//                        source and destination ports must be set to 0

struct wldr_state;
typedef struct wldr_state Wldr;

Wldr *wldr_Init();

void wldr_Destroy(Wldr **wldrPtr);

void wldr_ResetState(Wldr *wldr);

void wldr_SetLabel(Wldr *wldr, msgbuf_t *message);

void wldr_DetectLosses(Wldr *wldr, const Connection *conn, msgbuf_t *message);

void wldr_HandleWldrNotification(Wldr *wldr, const Connection *conn,
                                 msgbuf_t *message);
#endif  // wldr_h
