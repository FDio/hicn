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
 * \file objects/connection.h
 * \brief Connection.
 */

#ifndef HICNCTRL_OBJECTS_CONNECTION_H
#define HICNCTRL_OBJECTS_CONNECTION_H

#include <stdint.h>
#include <hicn/face.h>

#include "base.h"

/*
 * NOTE :
 *  - interface_name is mainly used to derive listeners from connections,
 * but is not itself used to create connections.
 */
typedef struct {
  uint32_t id;                        /* Kr. */
  char name[SYMBOLIC_NAME_LEN];       /* K.w */
  char interface_name[INTERFACE_LEN]; /* Kr. */
  netdevice_type_t netdevice_type;    /* .r. */
  face_type_t type;                   /* .rw */
  int family;                         /* .rw */
  hicn_ip_address_t local_addr;       /* .rw */
  uint16_t local_port;                /* .rw */
  hicn_ip_address_t remote_addr;      /* .rw */
  uint16_t remote_port;               /* .rw */
  face_state_t admin_state;           /* .rw */
  uint32_t priority;                  /* .rw */
  policy_tags_t tags;                 /* .rw */
  face_state_t state;                 /* .r. */
} hc_connection_t;

#define foreach_connection(VAR, data) foreach_type(hc_connection_t, VAR, data)

#define MAXSZ_HC_CONNECTION_                                   \
  MAXSZ_FACE_STATE_ + INTERFACE_LEN + SPACE + 2 * MAXSZ_URL_ + \
      MAXSZ_FACE_TYPE_ + SPACES(3)
#define MAXSZ_HC_CONNECTION MAXSZ_HC_CONNECTION_ + NULLTERM

int hc_connection_validate(const hc_connection_t *connection,
                           bool allow_partial);
int hc_connection_cmp(const hc_connection_t *c1, const hc_connection_t *c2);
int hc_connection_snprintf(char *s, size_t size,
                           const hc_connection_t *connection);

#endif /* HICNCTRL_OBJECTS_CONNECTION_H */
