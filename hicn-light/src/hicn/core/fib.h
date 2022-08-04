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

#ifndef HICNLIGHT_FIB_H
#define HICNLIGHT_FIB_H

#include "fib_entry.h"
#include "msgbuf.h"
#include <hicn/name.h>

#define _fib_var(x) _fib_##x

typedef struct fib_s fib_t;

fib_t *fib_create(void *forwarder);

void fib_free(fib_t *fib);

size_t fib_get_size(const fib_t *fib);

void fib_add(fib_t *fib, fib_entry_t *node);

fib_entry_t *fib_contains(const fib_t *fib, const hicn_prefix_t *prefix);

void fib_remove(fib_t *fib, const hicn_prefix_t *prefix, unsigned conn_id);

void fib_remove_entry_connection(fib_t *fib, fib_entry_t *entry,
                                 unsigned conn_id, fib_entry_t **removed_entry);

void fib_remove_name_connection(fib_t *fib, const hicn_prefix_t *prefix,
                                unsigned conn_id);

void fib_remove_entry(fib_t *fib, fib_entry_t *entry);

void fib_remove_connection(fib_t *fib, unsigned conn_id,
                           fib_entry_t ***removed_entries,
                           size_t *num_removed_entries);

fib_entry_t *fib_match_msgbuf(const fib_t *fib, const msgbuf_t *msgbuf);

fib_entry_t *fib_match_prefix(const fib_t *fib, const hicn_prefix_t *prefix);

fib_entry_t *fib_match_name(const fib_t *fib, const hicn_name_t *name);

size_t fib_get_entry_array(const fib_t *fib, fib_entry_t ***array_p);

/*
 * NOTE : do not use return on the loop body to avoid leaking memory
 */
#define fib_foreach_entry(FIB, ENTRY, BODY)                            \
  do {                                                                 \
    fib_entry_t **_fib_var(array);                                     \
    size_t _fib_var(n) = fib_get_entry_array((FIB), &_fib_var(array)); \
    size_t _fib_var(i);                                                \
    fib_entry_t *ENTRY;                                                \
    for (_fib_var(i) = 0; _fib_var(i) < _fib_var(n); _fib_var(i)++) {  \
      ENTRY = _fib_var(array)[_fib_var(i)];                            \
      do {                                                             \
        BODY                                                           \
      } while (0);                                                     \
    }                                                                  \
    free(_fib_var(array));                                             \
  } while (0)

bool fib_is_valid(const fib_t *fib);
bool _fib_check_preorder(const fib_t *fib, const hicn_prefix_t **prefix_array,
                         bool *used_array, size_t size);

#define fib_check_preorder(F, PA, UA) \
  _fib_check_preorder(F, PA, UA, sizeof(PA) / sizeof(hicn_prefix_t *))

void fib_dump(const fib_t *fib);

#endif /* HICNLIGHT_FIB_H */
