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

/**
 * \file address.c
 * \brief Implementation of Address
 */

#include <hicn/core/address.h>
#include <hicn/util/sstrncpy.h>

int address_from_ip_port(address_t *address, int family, ip_address_t *addr,
                         uint16_t port) {
  switch (family) {
    case AF_INET:
      *address = ADDRESS4(ntohl(addr->v4.as_inaddr.s_addr), ntohs(port));
      break;
    case AF_INET6:
      *address = ADDRESS6(addr->v6.as_in6addr, ntohs(port));
      break;
    default:
      return -1;
  }
  return 0;
}

const char *_address_family_str[] = {
    [AF_INET] = "AF_INET",
    [AF_INET6] = "AF_INET6",
};

int address_to_string(const address_t *address, char *addr_str, int *port) {
  const int SUCCESS = 0;
  char port_str[NI_MAXSERV];
  struct sockaddr_storage addr = address->as_ss;
  socklen_t addr_len = sizeof(addr);

  int result =
      getnameinfo((struct sockaddr *)&addr, addr_len, addr_str, NI_MAXHOST,
                  port_str, sizeof(port_str), NI_NUMERICHOST | NI_NUMERICSERV);

  if (result != SUCCESS) {
    strcpy_s(addr_str, NI_MAXHOST, "N/A");
    if (port != NULL) *port = -1;
    return result;
  }

  if (port != NULL) *port = atoi(port_str);
  return SUCCESS;
}

address_t _ADDRESS4_LOCALHOST(uint16_t port) {
  return ADDRESS4_LOCALHOST(port);
}
