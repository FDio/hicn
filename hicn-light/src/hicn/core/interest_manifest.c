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

#include "interest_manifest.h"

int_manifest_split_strategy_t disaggregation_strategy =
    INT_MANIFEST_SPLIT_MAX_N_SUFFIXES;
unsigned N_SUFFIXES_PER_SPIT = 256;

bool interest_manifest_is_valid(interest_manifest_header_t *int_manifest_header,
                                size_t payload_length) {
  if (int_manifest_header->n_suffixes == 0 ||
      int_manifest_header->n_suffixes > MAX_SUFFIXES_IN_MANIFEST) {
    ERROR("Manifest with invalid number of suffixes (%d)",
          int_manifest_header->n_suffixes);
    return false;
  }

  uint32_t empty_bitmap[BITMAP_SIZE] = {0};
  if (memcmp(empty_bitmap, int_manifest_header->request_bitmap,
             sizeof(empty_bitmap)) == 0) {
    ERROR("Manifest with empty bitmap");
    return false;
  }

  if (payload_length - sizeof(interest_manifest_header_t) !=
      int_manifest_header->n_suffixes * sizeof(u32)) {
    ERROR("Size of suffixes in intereset manifest (%d) is not equal to %d",
          payload_length - sizeof(interest_manifest_header_t),
          int_manifest_header->n_suffixes * sizeof(u32));
    return false;
  }

  return true;
}

int interest_manifest_update_bitmap(const u32 *initial_bitmap,
                                    u32 *bitmap_to_update, int start, int n,
                                    int max_suffixes) {
  int i = start, n_ones = 0;
  while (i < n) {
    if (is_bit_set(initial_bitmap, i)) {
      set_bit(bitmap_to_update, i);
      n_ones++;
    }
    i++;

    if (n_ones == max_suffixes) break;
  }

  return i;
}
