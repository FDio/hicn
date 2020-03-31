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
#ifndef fib_h
#define fib_h

#include <hicn/base/msgbuf.h>
#include <hicn/core/name.h>
#include <hicn/core/fib_entry.h>
#include <hicn/core/fib_entry_list.h>

typedef struct fib_s fib_t;

fib_t * fib_create(void * forwarder);

void fib_free(fib_t * fib);

void fib_add(fib_t *fib, fib_entry_t * node);

fib_entry_t * fib_contains(const fib_t * fib, const Name * prefix);

void fib_remove(fib_t * fib, const Name * prefix, unsigned conn_id);

void fib_remove_connection_id(fib_t *fib, unsigned conn_id);

size_t fib_length(const fib_t *fib);

fib_entry_t * fib_match_message(const fib_t * fib, const msgbuf_t * interest_msgbuf);
fib_entry_t * fib_match_name(const fib_t * fib, const Name * name);
fib_entry_t * fib_match_bitvector(const fib_t * fib, const NameBitvector * name);

fib_entry_list_t *fib_get_entries(const fib_t *fib);

#endif  // fib_h
