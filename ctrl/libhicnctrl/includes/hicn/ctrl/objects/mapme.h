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
 * \file objects/mapme.h
 * \brief MAP-Me.
 */

#ifndef HICNCTRL_OBJECTS_MAPME_H
#define HICNCTRL_OBJECTS_MAPME_H

typedef enum {
  MAPME_TARGET_ENABLE,
  MAPME_TARGET_DISCOVERY,
  MAPME_TARGET_TIMESCALE,
  MAPME_TARGET_RETX,
} mapme_target_t;

static inline mapme_target_t mapme_target_from_str(char *mapme_target_str) {
  if (strcasecmp(mapme_target_str, "enable") == 0)
    return MAPME_TARGET_ENABLE;
  else if (strcasecmp(mapme_target_str, "discovery") == 0)
    return MAPME_TARGET_DISCOVERY;
  else if (strcasecmp(mapme_target_str, "timescale") == 0)
    return MAPME_TARGET_TIMESCALE;
  else
    return MAPME_TARGET_RETX;
}

#define MAX_MAPME_ARG_LEN 30

typedef struct {
  mapme_target_t target;
  // Command argument stored as a string
  // before being parsed into 'enabled' or 'timescale'
  char unparsed_arg[MAX_MAPME_ARG_LEN];

  uint8_t enabled;     // 1 = on, 0 = off
  uint32_t timescale;  // Milliseconds

  hicn_ip_address_t address;
  int family;
  u8 len;
} hc_mapme_t;

#endif /* HICNCTRL_OBJECTS_MAPME_H */
