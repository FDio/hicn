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

#ifndef HICNLIGHT_PROBE_GENERATOR
#define HICNLIGHT_PROBE_GENERATOR

#include <hicn/util/khash.h>
#include <hicn/core/ticks.h>
#include <hicn/core/msgbuf.h>

#define MIN_PROBE_SUFFIX 0xefffffff
#define MAX_PROBE_SUFFIX 0xffffffff - 1

KHASH_MAP_INIT_INT64(bp_map, Ticks);

struct forwarder_s;

typedef struct probe_generator {
  kh_bp_map_t *ticks_by_seq;
} probe_generator_t;

probe_generator_t *create_probe_generator();

void destroy_probe_generator(probe_generator_t *pg);

int generate_probe(probe_generator_t *pg, const msgbuf_t *msgbuf,
                   const struct forwarder_s *forwarder, unsigned nexthop);

Ticks register_probe(probe_generator_t *pg, unsigned seq);

Ticks get_probe_send_time(probe_generator_t *pg, unsigned seq);

void delete_probe(probe_generator_t *pg, unsigned seq);

void delete_all_probes(probe_generator_t *pg);

#endif /* HICNLIGHT_PROBE_GENERATOR */
