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

/**
 * \file nexthops.c
 * \brief Nexthops implementation
 */

#include "nexthops.h"

int nexthops_disable(nexthops_t *nexthops, off_t offset) {
  if (offset >= nexthops->num_elts) return -1;
  nexthops->flags |= (1 << offset);
  nexthops->cur_elts--;
  return 0;
}

void nexthops_reset(nexthops_t *nexthops) {
  nexthops->flags = 0;
  nexthops->cur_elts = nexthops->num_elts;
}

off_t nexthops_add(nexthops_t *nexthops, nexthop_t nexthop) {
  off_t id;
  unsigned i, n;
  nexthops_enumerate(nexthops, i, n, {
    if (n == nexthop) return i;
  });
  id = nexthops->num_elts++;
  nexthops->elts[id] = nexthop;
  nexthops_reset(nexthops);
  return id;
}

off_t nexthops_remove(nexthops_t *nexthops, nexthop_t nexthop) {
  unsigned i, n;
  nexthops_enumerate(nexthops, i, n, {
    if (n == nexthop) {
      nexthops->num_elts--;
      nexthops->elts[i] = nexthops->elts[nexthops->num_elts];
      nexthops->state[i] = nexthops->state[nexthops->num_elts];
      nexthops_reset(nexthops);
      return i;
    }
  });
  return INVALID_NEXTHOP;
}

bool nexthops_contains(nexthops_t *nexthops, unsigned nexthop) {
  unsigned n;
  nexthops_foreach(nexthops, n, {
    if (n == nexthop) return true;
  });
  return false;
}

off_t nexthops_find(nexthops_t *nexthops, unsigned nexthop) {
  unsigned i, n;
  nexthops_enumerate(nexthops, i, n, {
    if (n == nexthop) return i;
  });
  return INVALID_NEXTHOP;
}

unsigned nexthops_get_one(nexthops_t *nexthops) {
  unsigned n;
  nexthops_foreach(nexthops, n, { return n; });
  return INVALID_NEXTHOP;
}

int nexthops_select(nexthops_t *nexthops, off_t i) {
  if (i >= nexthops->num_elts) return -1;
  nexthops->flags = ~0; /* all 1, could be limited to num_elts */
  nexthops->flags &= ~(1 << (i));
  nexthops->cur_elts = 1;
  return 0;
}

#ifdef WITH_POLICY

void nexthops_set_priority(nexthops_t *nexthops, nexthop_t nexthop,
                           int priority) {
  unsigned i;
  nexthop_t nh;
  nexthops_enumerate(nexthops, i, nh, {
    if (nexthop == nh) nexthops_set_priority_by_id(nexthops, i, priority);
  });
}

void nexthops_set_priority_by_id(nexthops_t *nexthops, off_t i, int priority) {
  nexthops->state[i].priority = priority;
}

void nexthops_reset_priority(nexthops_t *nexthops, nexthop_t nexthop) {
  nexthops_set_priority(nexthops, nexthop, DEFAULT_PRIORITY);
}

void nexthops_reset_priority_by_id(nexthops_t *nexthops, off_t i) {
  nexthops_set_priority_by_id(nexthops, i, DEFAULT_PRIORITY);
}

void nexthops_reset_priorities(nexthops_t *nexthops) {
  unsigned i;
  nexthop_t nh;
  nexthops_enumerate(nexthops, i, nh, {
    (void)nh;
    nexthops_reset_priority(nexthops, i);
  });
}

bool nexthops_equal(nexthops_t *a, nexthops_t *b) {
  unsigned n;
  if (nexthops_get_len(a) != nexthops_get_len(b)) return false;
  nexthops_foreach(a, n, {
    if (!nexthops_contains(b, n)) return false;
  });
  return true;
}

void nexthops_copy(nexthops_t *src, nexthops_t *dst) {
  for (unsigned i = 0; i < MAX_NEXTHOPS; i++) {
    dst->elts[i] = src->elts[i];
    dst->state[i] = src->state[i];
  }
  dst->num_elts = src->num_elts;
  dst->flags = src->flags;
  dst->cur_elts = src->cur_elts;
}

#endif /* WITH_POLICY */
