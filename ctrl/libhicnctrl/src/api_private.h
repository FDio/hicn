/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

#ifndef HICN_API_PRIVATE_H
#define HICN_API_PRIVATE_H

#include <hicn/ctrl/api.h>
#include <hicn/util/token.h>
#include <hicn/util/log.h>
#include <hicn/util/map.h>
#ifndef HICN_VPP_PLUGIN
#include <hicn/util/sstrncpy.h>
#endif
#include <hicn/validation.h>
#include <ctype.h>

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(*array))

/*
 * Input validation
 */

static inline bool IS_VALID_ADDRESS(const hicn_ip_address_t *addr, int family) {
  char addr_str[INET6_ADDRSTRLEN];
  return !hicn_ip_address_empty(addr) &&
         hicn_ip_address_ntop(addr, addr_str, INET6_ADDRSTRLEN, family) >= 0;
}

static inline bool IS_VALID_PREFIX_LEN(u8 len) {
  return len <= MAX_IPV6_PREFIX_LEN;
}

// https://github.com/shemminger/iproute2/blob/50b668bdbf0ebc270495eb4b352d0c3982159d0a/lib/utils.c#L825
static inline bool IS_VALID_INTERFACE_NAME(const char *name) {
  size_t len = strnlen_s(name, INTERFACE_LEN);
  if (len == 0 || len >= IFNAMSIZ) return true;

  while (*name) {
    if (*name == '/' || isspace(*name)) return false;
    ++name;
  }

  return true;
}

static inline bool IS_VALID_NAME(const char *name) {
  return is_symbolic_name(name, SYMBOLIC_NAME_LEN);
}

static inline bool IS_VALID_STR_ID(const char *name) {
  return is_number(name, SYMBOLIC_NAME_LEN);
}

#define IS_VALID_TYPE(x) IS_VALID_ENUM_TYPE(FACE_TYPE, x)
#define IS_VALID_ADDR_TYPE(x) ((x >= ADDR_INET) && (x <= ADDR_UNIX))
#define IS_VALID_FACE_ID(x) ((x) != INVALID_FACE_ID)

#define IS_VALID_ID(x) (1)
#define IS_VALID_POLICY(x) (1)

typedef struct hc_sock_impl_s hc_sock_impl_t;

int hc_data_ensure_available(hc_data_t *data, size_t count);
u8 *hc_data_get_next(hc_data_t *data);

int hc_listener_to_face(const hc_listener_t *listener, hc_face_t *face);

int hc_connection_to_face(const hc_connection_t *connection, hc_face_t *face);

int hc_face_to_listener(const hc_face_t *face, hc_listener_t *listener);

int hc_connection_to_local_listener(const hc_connection_t *connection,
                                    hc_listener_t *listener);

int hc_face_to_connection(const hc_face_t *face, hc_connection_t *connection,
                          bool generate_name);

#endif  // HICN_API_PRIVATE_H
