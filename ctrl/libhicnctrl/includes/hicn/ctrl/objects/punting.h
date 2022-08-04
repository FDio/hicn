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
 * \file objects/punting.h
 * \brief Punting
 */

#ifndef HICNCTRL_OBJECTS_PUNTING_H
#define HICNCTRL_OBJECTS_PUNTING_H

typedef struct {
  face_id_t face_id; /* Kr. */  // XXX listener id, could be NULL for all ?
  int family;                   /* Krw */
  hicn_ip_address_t prefix;     /* krw */
  u8 prefix_len;                /* krw */
} hc_punting_t;

int hc_punting_validate(const hc_punting_t *punting);
int hc_punting_cmp(const hc_punting_t *c1, const hc_punting_t *c2);

#define foreach_punting(VAR, data) foreach_type(hc_punting_t, VAR, data)

#define MAXSZ_HC_PUNTING_ 0
#define MAXSZ_HC_PUNTING MAXSZ_HC_PUNTING_ + NULLTERM

int hc_punting_snprintf(char *s, size_t size, hc_punting_t *punting);

#endif /* HICNCTRL_OBJECTS_PUNTING_H */
