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

#include "hicn_light_common.h"

TYPEDEF_MAP(hc_sock_map, int, hc_sock_request_t *, int_cmp, int_snprintf,
            generic_snprintf);

hc_sock_request_t *hc_sock_request_create(int seq, hc_data_t *data,
                                          HC_PARSE parse) {
  assert(data);

  hc_sock_request_t *request = malloc(sizeof(hc_sock_request_t));
  if (!request) return NULL;
  request->seq = seq;
  request->data = data;
  request->parse = parse;
  return request;
}

void hc_sock_light_request_free(hc_sock_request_t *request) { free(request); }
