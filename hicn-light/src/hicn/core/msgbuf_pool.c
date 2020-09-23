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
 * @file msgbuf_pool.c
 * @brief Implementation of hICN packet pool.
 */

#include "../base/pool.h"
#include "msgbuf_pool.h"

#define PACKET_POOL_DEFAULT_INIT_SIZE 1024

msgbuf_pool_t *
_msgbuf_pool_create(size_t init_size, size_t max_size)
{
    msgbuf_pool_t * msgbuf_pool = malloc(sizeof(msgbuf_pool_t));

    if (init_size == 0)
        init_size = PACKET_POOL_DEFAULT_INIT_SIZE;

    pool_init(msgbuf_pool->buffers, init_size, 0);

    return msgbuf_pool;
}

void
msgbuf_pool_free(msgbuf_pool_t * msgbuf_pool)
{
    pool_free(msgbuf_pool->buffers);
    free(msgbuf_pool);
}

off_t
msgbuf_pool_get(msgbuf_pool_t * msgbuf_pool, msgbuf_t ** msgbuf)
{
    return pool_get(msgbuf_pool->buffers, *msgbuf);
}

void
msgbuf_pool_put(msgbuf_pool_t * msgbuf_pool, msgbuf_t * msgbuf)
{
    pool_put(msgbuf_pool->buffers, msgbuf);
}

int
msgbuf_pool_getn(msgbuf_pool_t * msgbuf_pool, msgbuf_t ** msgbuf, size_t n)
{
    for (unsigned i = 0; i < n; i++) {
        // If not able to get the msgbuf
        if (msgbuf_pool_get(msgbuf_pool, &msgbuf[i]) < 0) {
            // Release all the msgbufs retrieved so far
            for (unsigned j = 0; j < i; j++) {
                msgbuf_pool_put(msgbuf_pool, msgbuf[j]);
            }
            return -1;
        }
    }
    return 0;
}

off_t
msgbuf_pool_get_id(msgbuf_pool_t * msgbuf_pool, msgbuf_t * msgbuf)
{
    return msgbuf - msgbuf_pool->buffers;
}

msgbuf_t *
msgbuf_pool_at(const msgbuf_pool_t * msgbuf_pool, off_t id)
{
    return msgbuf_pool->buffers + id;
}
