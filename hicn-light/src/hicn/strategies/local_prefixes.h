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
 * struct used to store prefixes that are served locally.
 * these prefixes are used in mapme messages to tell to the server which
 * path to use to retrive the content produced locally.
 * using this strategy the path selection done by the client can be
 * replicated at the server
 */

#ifndef HICNLIGHT_LOCAL_PREFIXES_H
#define HICNLIGHT_LOCAL_PREFIXES_H

#include <hicn/name.h>

typedef struct local_prefixes_s local_prefixes_t;

local_prefixes_t* create_local_prefixes();

void free_local_prefixes(local_prefixes_t* lp);

unsigned local_prefixes_get_len(local_prefixes_t* prefixes);

void local_prefixes_add_prefixes(local_prefixes_t* prefixes,
                                 local_prefixes_t* new_prefixes);

void local_prefixes_add_prefix(local_prefixes_t* prefixes,
                               const hicn_prefix_t* prefix);

void update_remote_node_paths(const void* nexthops, const void* forwarder,
                              local_prefixes_t* prefixes);

#endif /* HICNLIGHT_LOCAL_PREFIXES */
