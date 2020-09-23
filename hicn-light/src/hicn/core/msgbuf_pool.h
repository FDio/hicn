/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

/**
 * @file msgbuf_pool.h
 * @brief hICN msgbuf pool.
 *
 * THe msgbuf pool is used to store packet payloads while the packets are in
 * transit, as well as holding them into the packet cache (PIT, CSS), WLDR,
 * mapme, etc.
 *
 * Control packets might receive a special treatment in that they are eventually
 * transformed into a ack/nack, but this should not affect any part of this
 * design.
 *
 * Do we need a reference count, or simply a lock ?
 * What about weak references ?
 * We need to be sure that a pool element is never referenced ever again after
 * it is deleted from the pool as its ID might be reaffected.
 *
 * It might even be better to store references to msgbuf's as they might hold
 * additional information of interest about the packet... a bit like a skbuff in
 * linux. Is this relevant for the packet cache ?
 */

#ifndef HICNLIGHT_MSGBUF_POOL_H
#define HICNLIGHT_MSGBUF_POOL_H

#include "msgbuf.h"

#define MTU 1500

typedef struct {
    msgbuf_t * buffers;
} msgbuf_pool_t;

// 0 for init size means a default value (of 1024)
// 0 for max_size means no limit
msgbuf_pool_t * _msgbuf_pool_create(size_t init_size, size_t max_size);

#define msgbuf_pool_create() _msgbuf_pool_create(0, 0)

void msgbuf_pool_free(msgbuf_pool_t * msgbuf_pool);

int msgbuf_pool_get(msgbuf_pool_t * msgbuf_pool, msgbuf_t * msgbuf);

int msgbuf_pool_getn(msgbuf_pool_t * msgbuf_pool, msgbuf_t ** msgbuf, size_t n);

off_t msgbuf_pool_get_id(msgbuf_pool_t * msgbuf_pool, msgbuf_t * msgbuf);

msgbuf_t * msgbuf_pool_at(msgbuf_pool_t * msgbuf_pool, off_t id);

#endif /* HICNLIGHT_MSGBUF_POOL_H */
