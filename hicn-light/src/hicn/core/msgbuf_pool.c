/*
 * Copyright (c) 2021-2022 Cisco and/or its affiliates.
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

#include <hicn/util/pool.h>
#include <hicn/util/log.h>
#include "msgbuf_pool.h"

msgbuf_pool_t *_msgbuf_pool_create(size_t init_size, size_t max_size) {
  msgbuf_pool_t *msgbuf_pool = malloc(sizeof(msgbuf_pool_t));

  if (init_size == 0) init_size = PACKET_POOL_DEFAULT_INIT_SIZE;

  pool_init(msgbuf_pool->buffers, init_size, 0);

  return msgbuf_pool;
}

void msgbuf_pool_free(msgbuf_pool_t *msgbuf_pool) {
  pool_free(msgbuf_pool->buffers);
  free(msgbuf_pool);
}

off_t msgbuf_pool_get(msgbuf_pool_t *msgbuf_pool, msgbuf_t **msgbuf) {
  off_t id = pool_get(msgbuf_pool->buffers, *msgbuf);
  (*msgbuf)->refs = 0;
  return id;
}

void msgbuf_pool_put(msgbuf_pool_t *msgbuf_pool, msgbuf_t *msgbuf) {
  pool_put(msgbuf_pool->buffers, msgbuf);
}

int msgbuf_pool_getn(msgbuf_pool_t *msgbuf_pool, msgbuf_t **msgbuf, size_t n) {
  // CAVEAT: Resize at the beginning otherwise the resize can be
  // triggered by an intermediate msgbuf_pool_put, making the
  // buffers previously retrieved invalid
  uint64_t remaining_pool_space =
      pool_get_free_indices_size(msgbuf_pool->buffers);
  while (remaining_pool_space < n) {
    _pool_resize((void **)&(msgbuf_pool->buffers), sizeof(msgbuf_t));

    remaining_pool_space = pool_get_free_indices_size(msgbuf_pool->buffers);
  }

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

off_t msgbuf_pool_get_id(msgbuf_pool_t *msgbuf_pool, msgbuf_t *msgbuf) {
  return msgbuf - msgbuf_pool->buffers;
}

msgbuf_t *msgbuf_pool_at(const msgbuf_pool_t *msgbuf_pool, off_t id) {
  assert(msgbuf_id_is_valid(id));
  return msgbuf_pool->buffers + id;
}

void msgbuf_pool_acquire(msgbuf_t *msgbuf) { msgbuf->refs++; };

void msgbuf_pool_release(msgbuf_pool_t *msgbuf_pool, msgbuf_t **msgbuf_ptr) {
  msgbuf_t *msgbuf = *msgbuf_ptr;
  assert(msgbuf->refs > 0);
  msgbuf->refs--;

  if (msgbuf->refs == 0) {
    WITH_TRACE({
      off_t msgbuf_id = msgbuf_pool_get_id(msgbuf_pool, msgbuf);
      if (msgbuf_get_type(msgbuf) != HICN_PACKET_TYPE_INTEREST &&
          msgbuf_get_type(msgbuf) != HICN_PACKET_TYPE_DATA) {
        TRACE("Msgbuf %d (%p) - put to msgbuf pool", msgbuf_id, msgbuf);
      } else {
        char buf[MAXSZ_HICN_NAME];
        int rc =
            hicn_name_snprintf(buf, MAXSZ_HICN_NAME, msgbuf_get_name(msgbuf));
        if (rc < 0 || rc >= MAXSZ_HICN_NAME)
          snprintf(buf, MAXSZ_HICN_NAME, "%s", "(error)");
        const char *msgbuf_type_str =
            msgbuf_get_type(msgbuf) == HICN_PACKET_TYPE_INTEREST ? "interest"
                                                                 : "data";
        TRACE("Msgbuf %d (%p) - %s (%s) put to msgbuf pool", msgbuf_id, msgbuf,
              buf, msgbuf_type_str);
      }
    })

    msgbuf_pool_put(msgbuf_pool, msgbuf);
    *msgbuf_ptr = NULL;
  }
};

off_t msgbuf_pool_clone(msgbuf_pool_t *msgbuf_pool, msgbuf_t **new_msgbuf,
                        off_t orginal_msg_id) {
  msgbuf_t *original_msgbuf = msgbuf_pool_at(msgbuf_pool, orginal_msg_id);
  off_t offset = pool_get(msgbuf_pool->buffers, *new_msgbuf);
  memcpy(*new_msgbuf, original_msgbuf, sizeof(msgbuf_t));
  (*new_msgbuf)->refs = 0;
  return offset;
}
