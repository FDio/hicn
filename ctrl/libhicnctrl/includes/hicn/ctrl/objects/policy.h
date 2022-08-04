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
 * \file objects/policy.h
 * \brief Policy.
 */

#ifndef HICNCTRL_OBJECTS_POLICY_H
#define HICNCTRL_OBJECTS_POLICY_H

typedef struct {
  int family;                    /* Krw */
  hicn_ip_address_t remote_addr; /* krw */
  uint8_t len;                   /* krw */
  hicn_policy_t policy;          /* .rw */
} hc_policy_t;

#define foreach_policy(VAR, data) foreach_type(hc_policy_t, VAR, data)

/* TODO */
#define MAXSZ_HC_POLICY_ 0
#define MAXSZ_HC_POLICY MAXSZ_HC_POLICY_ + NULLTERM

int hc_policy_snprintf(char *s, size_t size, hc_policy_t *policy);
int hc_policy_validate(const hc_policy_t *policy);

#endif /* HICNCTRL_OBJECTS_POLICY_H */
