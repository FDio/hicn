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
 * \file objects/active_interface.h
 * \brief Route.
 */

#ifndef HICNCTRL_OBJECTS_ACTIVE_INTERFACE_H
#define HICNCTRL_OBJECTS_ACTIVE_INTERFACE_H

#include <hicn/ctrl/objects/face.h>

typedef struct {
  hicn_ip_prefix_t prefix;
  netdevice_flags_t interface_types;
} hc_active_interface_t;

#define foreach_active_interface(VAR, data) \
  foreach_type(hc_active_interface_t, VAR, data)

// XXX WRONG
#define MAXSZ_HC_ACTIVE_INTERFACE_ \
  MAXSZ_FACE_ID + 1 + MAXSZ_COST + 1 + MAXSZ_IP_ADDRESS + 1 + MAXSZ_LEN
#define MAXSZ_HC_ACTIVE_INTERFACE MAXSZ_HC_ACTIVE_INTERFACE_ + NULLTERM

int hc_active_interface_snprintf(char *s, size_t size,
                                 const hc_active_interface_t *active_interface);
int hc_active_interface_validate(const hc_active_interface_t *active_interface,
                                 bool allow_partial);

#endif
