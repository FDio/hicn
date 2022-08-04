
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
 * \file objects/strategy.h
 * \brief Strategy.
 */

#ifndef HICNCTRL_OBJECTS_STRATEGY_H
#define HICNCTRL_OBJECTS_STRATEGY_H

#include <hicn/strategy.h>

#define MAXSZ_STRATEGY_NAME 255

typedef struct {
  // The name is not set by the controller
  // but populated by the daemon
  char name[MAXSZ_STRATEGY_NAME];
  strategy_type_t type;
  hicn_ip_address_t address, local_address;
  int family, local_family;
  u8 len, local_len;
} hc_strategy_t;

#define foreach_strategy(VAR, data) foreach_type(hc_strategy_t, VAR, data)

#define MAXSZ_HC_STRATEGY_ MAXSZ_STRATEGY_NAME
#define MAXSZ_HC_STRATEGY MAXSZ_HC_STRATEGY_ + NULLTERM

int hc_strategy_snprintf(char *s, size_t size, const hc_strategy_t *strategy);

#endif /* HICNCTRL_OBJECTS_STRATEGY_H */
