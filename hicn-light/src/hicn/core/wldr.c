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
#include <hicn/core/connection.h>
#include <hicn/core/forwarder.h>
#include <hicn/core/wldr.h>
#include <stdint.h>
#include <stdio.h>

struct wldr_buffer {
  msgbuf_t *message;
  uint8_t rtx_counter;
};

typedef struct wldr_buffer WldrBuffer;

struct wldr_state {
  uint16_t expected_label;
  uint16_t next_label;
  WldrBuffer *buffer[BUFFER_SIZE];
};

Wldr *wldr_Init() {
#if 0
  Wldr *wldr = parcMemory_AllocateAndClear(sizeof(Wldr));
  parcAssertNotNull(wldr, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(Wldr));
  wldr->expected_label = 1;
  wldr->next_label = 1;
  for (int i = 0; i < BUFFER_SIZE; i++) {
    WldrBuffer *entry = parcMemory_AllocateAndClear(sizeof(WldrBuffer));
    parcAssertNotNull(
        entry,
        "WldrBuffer init: parcMemory_AllocateAndClear(%zu) returned NULL",
        sizeof(WldrBuffer));
    entry->message = NULL;
    entry->rtx_counter = 0;
    wldr->buffer[i] = entry;
  }
  return wldr;
#else
  return NULL;
#endif
}

void wldr_ResetState(Wldr *wldr) {
#if 0
  wldr->expected_label = 1;
  wldr->next_label = 1;
  for (int i = 0; i < BUFFER_SIZE; i++) {
    wldr->buffer[i]->message = NULL;
    wldr->buffer[i]->rtx_counter = 0;
  }
#endif
}

void wldr_Destroy(Wldr **wldrPtr) {
#if 0
  Wldr *wldr = *wldrPtr;
  for (unsigned i = 0; i < BUFFER_SIZE; i++) {
    if (wldr->buffer[i]->message != NULL) {
      message_Release(&(wldr->buffer[i]->message));
      parcMemory_Deallocate((void **)&(wldr->buffer[i]));
    }
  }
  parcMemory_Deallocate((void **)&wldr);
  *wldrPtr = NULL;
#endif
}

#if 0
static void _wldr_RetransmitPacket(Wldr *wldr, const Connection *conn,
                                   uint16_t label) {
  if (wldr->buffer[label % BUFFER_SIZE]->message == NULL) {
    // the required message for retransmission is not in the buffer
    return;
  }

  if (wldr->buffer[label % BUFFER_SIZE]->rtx_counter < MAX_RTX) {
    msgbuf_t *msg = wldr->buffer[label % BUFFER_SIZE]->message;
    message_SetWldrLabel(msg, wldr->next_label);

    if (wldr->buffer[wldr->next_label % BUFFER_SIZE]->message != NULL) {
      message_Release(&(wldr->buffer[wldr->next_label % BUFFER_SIZE]->message));
    }

    wldr->buffer[wldr->next_label % BUFFER_SIZE]->message = msg;
    wldr->buffer[wldr->next_label % BUFFER_SIZE]->rtx_counter =
        wldr->buffer[label % BUFFER_SIZE]->rtx_counter + 1;
    message_Acquire(wldr->buffer[wldr->next_label % BUFFER_SIZE]->message);
    wldr->next_label++;
    connection_ReSend(conn, msg, false);
  }
}
#endif

#if 0
static void _wldr_SendWldrNotification(Wldr *wldr, const Connection *conn,
                                       msgbuf_t *message, uint16_t expected_lbl,
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
      message_CreateWldrNotification(message, expected_lbl, received_lbl);
  parcAssertNotNull(notification, "Got null from CreateWldrNotification");
  connection_ReSend(conn, notification, true);
}
#endif

void wldr_SetLabel(Wldr *wldr, msgbuf_t *message) {
#if 0
  // in this function we send the packet for the first time
  // 1) we set the wldr label
  message_SetWldrLabel(message, wldr->next_label);

  // 2) we store the pointer to packet in the buffer
  if (wldr->buffer[wldr->next_label % BUFFER_SIZE]->message != NULL) {
    // release an old message if necessary
    message_Release(&(wldr->buffer[wldr->next_label % BUFFER_SIZE]->message));
  }

  // we need to acquire the message to avoid that it gets destroyed
  message_Acquire(message);

  wldr->buffer[wldr->next_label % BUFFER_SIZE]->message = message;
  wldr->buffer[wldr->next_label % BUFFER_SIZE]->rtx_counter = 0;
  wldr->next_label++;
  if (wldr->next_label ==
      0)  // we alwasy skip label 0 beacause it means that wldr is not active
    wldr->next_label++;
#endif
}

void wldr_DetectLosses(Wldr *wldr, const Connection *conn, msgbuf_t *message) {
#if 0
  if (message_HasWldr(message)) {
    // this is a normal wldr packet
    uint16_t pkt_lbl = (uint16_t)message_GetWldrLabel(message);
    if (pkt_lbl != wldr->expected_label) {
      // if the received packet label is 1 and the expected packet label >
      // pkt_lbl usually we are in the case where a remote note disconnected for
      // a while and reconnected on this same connection, so the two nodes are
      // out of synch for this reason we do not send any notification, we just
      // synch the labels

      if ((pkt_lbl != 1) || (wldr->expected_label < pkt_lbl)) {
        _wldr_SendWldrNotificaiton(wldr, conn, message, wldr->expected_label,
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

void wldr_HandleWldrNotification(Wldr *wldr, const Connection *conn,
                                 msgbuf_t *message) {
#if 0
  uint16_t expected_lbl = (uint16_t)message_GetWldrExpectedLabel(message);
  uint16_t received_lbl = (uint16_t)message_GetWldrLastReceived(message);
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
