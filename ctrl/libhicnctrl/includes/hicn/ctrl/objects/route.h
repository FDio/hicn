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
 * \file objects/route.h
 * \brief Route.
 */

#ifndef HICNCTRL_OBJECTS_ROUTE_H
#define HICNCTRL_OBJECTS_ROUTE_H

#include <hicn/ctrl/objects/face.h>

typedef struct {
  face_id_t face_id; /* Kr. ID (used when face and face_name == NULL) */
  char face_name[SYMBOLIC_NAME_LEN]; /* Kr.  a name or an ID (if integer), used
                                        if face is NULL */
  int family;                        /* Krw */
  hicn_ip_address_t remote_addr;     /* krw */
  uint8_t len;                       /* krw */
  uint16_t cost;                     /* .rw */
  hc_face_t face; /* use by default if not NULL, otherwise look at face_name,
                     then face_id */
} hc_route_t;

#define foreach_route(VAR, data) foreach_type(hc_route_t, VAR, data)

#define MAX_COST 65535
#define MAXSZ_COST 5
#define MAX_LEN 255
#define MAXSZ_LEN 3

#define MAXSZ_HC_ROUTE_ \
  MAXSZ_FACE_ID + 1 + MAXSZ_COST + 1 + MAXSZ_IP_ADDRESS + 1 + MAXSZ_LEN
#define MAXSZ_HC_ROUTE MAXSZ_HC_ROUTE_ + NULLTERM

int hc_route_snprintf(char *s, size_t size, const hc_route_t *route);
int hc_route_validate(const hc_route_t *route, bool allow_partial);

#endif /* HICNCTRL_OBJECTS_ROUTE_H */
