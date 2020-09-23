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
 * The msgbuf pool is used to store packet payloads while the packets are in
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

/**
 * @brief Allocate and initialize a msgbuf pool structure (helper).
 *
 * @param[in] init_size Number of buffers that can be stored in msgbuf pool.
 * @param[in] max_size Maximum size.
 * @return msgbuf_pool_t* Pointer to the msgbuf pool created.
 *
 * @note
 *  - 0 for init size means a default value (of 1024)
 *  - 0 for max_size means no limit
 */
msgbuf_pool_t * _msgbuf_pool_create(size_t init_size, size_t max_size);

/**
 * @brief Allocate and initialize a msgbuf pool data structure.
 *
 * @return msgbuf_pool_t* Pointer to the msgbuf pool created.
 */
#define msgbuf_pool_create() _msgbuf_pool_create(0, 0)

/**
 * @brief Free a msgbuf pool data structure.
 *
 * @param[in] msgbuf_pool Pointer to the msgbuf pool data structure to free.
 */
void msgbuf_pool_free(msgbuf_pool_t * msgbuf_pool);

/**
 * @brief Get a free msgbuf from the msgbuf pool data structure.
 *
 * @param[in] msgbuf_pool Pointer to the msgbuf pool data structure to use.
 * @param[in, out] msgbuf Empty msgbuf that will be used to return the
 * allocated one from the msgbuf pool.
 * @return off_t ID of the msgbuf requested.
 */
off_t msgbuf_pool_get(msgbuf_pool_t * msgbuf_pool, msgbuf_t ** msgbuf);

/**
 * @brief Release a msgbuf previously obtained, making it available to the msgbuf pool.
 *
 * @param[in] msgbuf_pool Pointer to the msgbuf pool data structure to use.
 * @param[in] msgbuf Pointer to the msgbuf to release.
 */
void msgbuf_pool_put(msgbuf_pool_t * msgbuf_pool, msgbuf_t * msgbuf);


/**
 * @brief Get multiple free msgbufs from the msgbuf pool data structure.
 *
 * @param[in] msgbuf_pool Pointer to the msgbuf pool data structure to use.
 * @param[in, out] msgbuf Pointer to the first empty msgbuf that will be used to
 * allocate the msgbufs.
 * @param[in] n Number of msgbufs requested.
 * @retval 0 Success.
 * @retval -1 Error.
 */
int msgbuf_pool_getn(msgbuf_pool_t * msgbuf_pool, msgbuf_t ** msgbuf, size_t n);

/**
 * @brief Get the ID corresponding to the msgbuf requested.
 *
 * @param[in] msgbuf_pool Pointer to the msgbuf pool data structure to use.
 * @param[in] msgbuf Pointer to the msgbuf to retrieve the ID for.
 * @return off_t ID of the msgbuf requested.
 */
off_t msgbuf_pool_get_id(msgbuf_pool_t * msgbuf_pool, msgbuf_t * msgbuf);

/**
 * @brief Get the msgbuf corresponding to the ID requested.
 *
 * @param[in] msgbuf_pool Pointer to the msgbuf pool data structure to use.
 * @param[in] id Index of the msgbuf to retrieve.
 * @return msgbuf_t* Pointer to the msgbuf corresponding to the ID requested.
 */
msgbuf_t * msgbuf_pool_at(const msgbuf_pool_t * msgbuf_pool, off_t id);

#endif /* HICNLIGHT_MSGBUF_POOL_H */
