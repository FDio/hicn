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
 * \file objects/listener.h
 * \brief Listener.
 */

#ifndef HICNCTRL_OBJECTS_LISTENER_H
#define HICNCTRL_OBJECTS_LISTENER_H

#include <stddef.h>  // offsetof
#include <stdint.h>
#include <hicn/face.h>

#include "base.h"

// FIXME the listener should not require any port for hICN...
typedef struct {
  char name[SYMBOLIC_NAME_LEN];       /* K.w */
  char interface_name[INTERFACE_LEN]; /* Kr. */
  uint32_t id;                        /* Kr. */
  face_type_t type;                   /* .rw */
  int family;                         /* .rw */
  hicn_ip_address_t local_addr;       /* .rw */
  uint16_t local_port;                /* .rw */
} hc_listener_t;

int hc_listener_validate(const hc_listener_t *listener, bool allow_partial);
int hc_listener_cmp(const hc_listener_t *l1, const hc_listener_t *l2);

#define foreach_listener(VAR, data) foreach_type(hc_listener_t, VAR, data)

#define MAXSZ_HC_LISTENER_ \
  INTERFACE_LEN + SPACE + MAXSZ_URL_ + SPACE + MAXSZ_FACE_TYPE_
#define MAXSZ_HC_LISTENER MAXSZ_HC_LISTENER_ + NULLTERM

int hc_listener_snprintf(char *s, size_t size, const hc_listener_t *listener);

#endif /* HICNCTRL_OBJECTS_LISTENER_H */
