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

#include "probe_generator.h"

#include <hicn/core/forwarder.h>
#include <hicn/core/nexthops.h>

// map functions
static void add_to_map(probe_generator_t *pg, unsigned seq, Ticks now) {
  khiter_t k;
  int ret;
  k = kh_put_bp_map(pg->ticks_by_seq, seq, &ret);
  kh_value(pg->ticks_by_seq, k) = now;
}

static Ticks get_from_map(probe_generator_t *pg, unsigned seq) {
  khiter_t k;
  k = kh_get_bp_map(pg->ticks_by_seq, seq);
  if (k == kh_end(pg->ticks_by_seq)) return 0;
  Ticks t = kh_value(pg->ticks_by_seq, k);
  return t;
}

static void remove_from_map(probe_generator_t *pg, unsigned seq) {
  khiter_t k;
  k = kh_get_bp_map(pg->ticks_by_seq, seq);
  if (k != kh_end(pg->ticks_by_seq)) kh_del_bp_map(pg->ticks_by_seq, k);
}

static void clear_map(probe_generator_t *pg) {
  kh_clear(bp_map, pg->ticks_by_seq);
}

// seq number generator

static uint32_t get_seq_number(probe_generator_t *pg) {
  uint32_t seq = 0;
  uint32_t try = 0;
  while (try < 3) {  // try up to 3 times
    seq =
        (rand() % (MAX_PROBE_SUFFIX - MIN_PROBE_SUFFIX + 1)) + MIN_PROBE_SUFFIX;
    Ticks time = get_from_map(pg, seq);
    if (time == 0) return seq;  // seq does not exists
    try++;
  }
  return 0;
}

// probing functions

probe_generator_t *create_probe_generator() {
  probe_generator_t *pg = calloc(1, sizeof(probe_generator_t));
  if (!pg) return NULL;

  pg->ticks_by_seq = kh_init_bp_map();
  return pg;
}

void destroy_probe_generator(probe_generator_t *pg) {
  kh_destroy_bp_map(pg->ticks_by_seq);
  free(pg);
}

int generate_probe(probe_generator_t *pg, const msgbuf_t *msgbuf,
                   const forwarder_t *forwarder, nexthop_t nexthop) {
  msgbuf_pool_t *msgbuf_pool = forwarder_get_msgbuf_pool(forwarder);
  connection_table_t *table = forwarder_get_connection_table(forwarder);
  const connection_t *conn = connection_table_get_by_id(table, nexthop);
  if (!conn) return -1;

  msgbuf_t *probe;
  off_t msg_id = msgbuf_pool_get_id(msgbuf_pool, (msgbuf_t *)msgbuf);
  off_t probe_offset = msgbuf_pool_clone(msgbuf_pool, &probe, msg_id);

  uint32_t seq = get_seq_number(pg);
  if (seq == 0) return -1;

  messageHandler_ModifySuffix(msgbuf_get_packet(probe), seq);
  connection_send(conn, probe_offset, true);
  connection_flush(conn);
  add_to_map(pg, seq, ticks_now());
  msgbuf_pool_put(msgbuf_pool, probe);

  return 0;
}

Ticks register_probe(probe_generator_t *pg, unsigned seq) {
  Ticks now = ticks_now();
  add_to_map(pg, seq, now);
  return now;
}

Ticks get_probe_send_time(probe_generator_t *pg, unsigned seq) {
  return get_from_map(pg, seq);
}

void delete_probe(probe_generator_t *pg, unsigned seq) {
  remove_from_map(pg, seq);
}

void delete_all_probes(probe_generator_t *pg) { clear_map(pg); }
