/*
 * Copyright (c) 2022 Cisco and/or its affiliates.
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

#ifndef HICNLIGHT_INTEREST_MANIFEST_H
#define HICNLIGHT_INTEREST_MANIFEST_H

#include <string.h>
#include <stdbool.h>

#include <hicn/util/log.h>
#include <hicn/base.h>

typedef enum {
  INT_MANIFEST_SPLIT_NONE,
  INT_MANIFEST_SPLIT_MAX_N_SUFFIXES
} int_manifest_split_strategy_t;

#define N_SUFFIXES_PER_SPIT 64
extern int_manifest_split_strategy_t disaggregation_strategy;

bool interest_manifest_is_valid(interest_manifest_header_t *int_manifest_header,
                                size_t payload_length);

int interest_manifest_update_bitmap(const u32 *initial_bitmap,
                                    u32 *bitmap_to_update, int start, int n,
                                    int max_suffixes);

#endif /* HICNLIGHT_INTEREST_MANIFEST_H */
