/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
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

#pragma once

#ifdef __linux__

#include <hicn/transport/portability/portability.h>
#include <hicn/transport/utils/log.h>

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <stdio.h>
#include <sys/socket.h>
#include <string>

#define LINK_LOCAL_PREFIX 0xfe80

namespace utils {

static TRANSPORT_ALWAYS_INLINE int retrieveInterfaceAddress(
    const std::string &interface_name, struct sockaddr_in6 *address) {
  struct ifaddrs *ifap, *ifa;
  char addr[INET6_ADDRSTRLEN];

  getifaddrs(&ifap);

  for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr->sa_family == AF_INET6 &&
        strcmp(ifa->ifa_name, interface_name.c_str()) == 0) {
      struct sockaddr_in6 *tmp = (struct sockaddr_in6 *)ifa->ifa_addr;
      uint16_t prefix = 0;
      memcpy(&prefix, tmp->sin6_addr.s6_addr, sizeof(uint16_t));

      if (htons(LINK_LOCAL_PREFIX) != prefix) {
        *address = *(struct sockaddr_in6 *)ifa->ifa_addr;
        getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in6), addr,
                    sizeof(addr), NULL, 0, NI_NUMERICHOST);
        TRANSPORT_LOGI("Interface: %s\tAddress: %s", ifa->ifa_name, addr);
      }
    }
  }

  freeifaddrs(ifap);

  return 0;
}

}  // namespace utils

#endif  // __linux__