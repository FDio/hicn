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

#include <parc/assert/parc_Assert.h>
#include <parc/logging/parc_LogReporterTextStdout.h>
#include <hicn/base/connection.h>
#include <hicn/core/forwarder.h>
#include <hicn/core/wldr.h>
#include <stdint.h>
#include <stdio.h>

typedef struct {
  msgbuf_t *msgbuf;
  uint8_t rtx_counter;
} wldr_buffer_t;

struct wldr_s {
  uint16_t expected_label;
  uint16_t next_label;
  wldr_buffer_t * buffer[BUFFER_SIZE];
};

wldr_t * wldr_create() {
#if 0
  wldr_t * wldr = parcMemory_AllocateAndClear(sizeof(Wldr));
  parcAssertNotNull(wldr, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(Wldr));
  wldr->expected_label = 1;
  wldr->next_label = 1;
  for (int i = 0; i < BUFFER_SIZE; i++) {
    wldr_buffer_t *entry = parcMemory_AllocateAndClear(sizeof(wldr_buffer_t));
    parcAssertNotNull(
        entry,
        "wldr_buffer_t init: parcMemory_AllocateAndClear(%zu) returned NULL",
        sizeof(wldr_buffer_t));
    entry->msgbuf = NULL;
    entry->rtx_counter = 0;
    wldr->buffer[i] = entry;
  }
  return wldr;
#else
  return NULL;
#endif
}

void wldr_ResetState(wldr_t * wldr) {
#if 0
  wldr->expected_label = 1;
  wldr->next_label = 1;
  for (int i = 0; i < BUFFER_SIZE; i++) {
    wldr->buffer[i]->msgbuf = NULL;
    wldr->buffer[i]->rtx_counter = 0;
  }
#endif
}

void wldr_Destroy(wldr_t * *wldrPtr) {
#if 0
  wldr_t * wldr = *wldrPtr;
  for (unsigned i = 0; i < BUFFER_SIZE; i++) {
    if (wldr->buffer[i]->msgbuf != NULL) {
      message_Release(&(wldr->buffer[i]->msgbuf));
      parcMemory_Deallocate((void **)&(wldr->buffer[i]));
    }
  }
  parcMemory_Deallocate((void **)&wldr);
  *wldrPtr = NULL;
#endif
}

#if 0
static void _wldr_RetransmitPacket(wldr_t * wldr, const connection_t * conn,
                                   uint16_t label) {
  if (wldr->buffer[label % BUFFER_SIZE]->msgbuf == NULL) {
    // the required message for retransmission is not in the buffer
    return;
  }

  if (wldr->buffer[label % BUFFER_SIZE]->rtx_counter < MAX_RTX) {
    msgbuf_t *msg = wldr->buffer[label % BUFFER_SIZE]->msgbuf;
    message_SetWldrLabel(msg, wldr->next_label);

    if (wldr->buffer[wldr->next_label % BUFFER_SIZE]->msgbuf != NULL) {
      msgbuf_Release(&(wldr->buffer[wldr->next_label % BUFFER_SIZE]->msgbuf));
    }

    wldr->buffer[wldr->next_label % BUFFER_SIZE]->msgbuf = msg;
    wldr->buffer[wldr->next_label % BUFFER_SIZE]->rtx_counter =
        wldr->buffer[label % BUFFER_SIZE]->rtx_counter + 1;
    message_Acquire(wldr->buffer[wldr->next_label % BUFFER_SIZE]->msgbuf);
    wldr->next_label++;
    connection_ReSend(conn, msg, false);
  }
}
#endif

#if 0
static void _wldr_SendWldrNotification(wldr_t * wldr, const connection_t * conn,
                                       msgbuf_t *msgbuf, uint16_t expected_lbl,
                                       uint16_t received_lbl) {
  // here we need to create a new packet that is used to send the wldr
  // notification to the prevoius hop. the destionation address of the
  // notification is the source address of the message for which we want to
  // create a notification. in fact, if message is an interest the prevoius hop
  // is identified by the src. if message is a data, we need to send the
  // notification message with the content name has a source address in this way
  // the message will be trapped by the pounting rules in the next hop We define
  // the notification as an interest message so that the NAT in the send
  // function will set the src address of the local connection. Notice that in
  // this way the notification packet will be dispaced to the right connection
  // at the next hop.

  msgbuf_t *notification =
      message_CreateWldrNotification(msgbuf, expected_lbl, received_lbl);
  parcAssertNotNull(notification, "Got null from CreateWldrNotification");
  connection_ReSend(conn, notification, true);
}
#endif

void wldr_SetLabel(wldr_t * wldr, msgbuf_t *msgbuf) {
#if 0
  // in this function we send the packet for the first time
  // 1) we set the wldr label
  message_SetWldrLabel(msgbuf, wldr->next_label);

  // 2) we store the pointer to packet in the buffer
  if (wldr->buffer[wldr->next_label % BUFFER_SIZE]->msgbuf != NULL) {
    // release an old message if necessary
    message_Release(&(wldr->buffer[wldr->next_label % BUFFER_SIZE]->msgbuf));
  }

  // we need to acquire the message to avoid that it gets destroyed
  message_Acquire(msgbuf);

  wldr->buffer[wldr->next_label % BUFFER_SIZE]->msgbuf = msgbuf;
  wldr->buffer[wldr->next_label % BUFFER_SIZE]->rtx_counter = 0;
  wldr->next_label++;
  if (wldr->next_label ==
      0)  // we alwasy skip label 0 beacause it means that wldr is not active
    wldr->next_label++;
#endif
}

void wldr_DetectLosses(wldr_t * wldr, const connection_t * conn, msgbuf_t *msgbuf) {
#if 0
  if (message_HasWldr(msgbuf)) {
    // this is a normal wldr packet
    uint16_t pkt_lbl = (uint16_t)message_GetWldrLabel(msgbuf);
    if (pkt_lbl != wldr->expected_label) {
      // if the received packet label is 1 and the expected packet label >
      // pkt_lbl usually we are in the case where a remote note disconnected for
      // a while and reconnected on this same connection, so the two nodes are
      // out of synch for this reason we do not send any notification, we just
      // synch the labels

      if ((pkt_lbl != 1) || (wldr->expected_label < pkt_lbl)) {
        _wldr_SendWldrNotificaiton(wldr, conn, msgbuf, wldr->expected_label,
                                   pkt_lbl);
      }

      // here we always synch
      wldr->expected_label = (uint16_t)(pkt_lbl + 1);
    } else {
      wldr->expected_label++;
      if (wldr->expected_label == 0)
        wldr->expected_label++;  // for the next_label we want to skip 0
    }
  }
#endif
}

void wldr_HandleWldrNotification(wldr_t * wldr, const connection_t * conn,
                                 msgbuf_t *msgbuf) {
#if 0
  uint16_t expected_lbl = (uint16_t)message_GetWldrExpectedLabel(msgbuf);
  uint16_t received_lbl = (uint16_t)message_GetWldrLastReceived(msgbuf);
  if ((wldr->next_label - expected_lbl) > BUFFER_SIZE) {
    // the packets are not in the buffer anymore
    return;
  }
  while (expected_lbl < received_lbl) {
    _wldr_RetransmitPacket(wldr, conn, expected_lbl);
    expected_lbl++;
  }
#endif
}
