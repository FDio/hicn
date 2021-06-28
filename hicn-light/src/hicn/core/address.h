/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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
 * \file address.h
 * \brief Address
 */

#ifndef HICNLIGHT_ADDRESS_H
#define HICNLIGHT_ADDRESS_H

#include <netinet/in.h>

#include <string.h> // memcmp
#include <hicn/util/ip_address.h>
#include <netinet/in.h>

typedef struct sockaddr_storage address_t;

#define address_equals(a, b) (memcmp(a, b, sizeof(address_t)) == 0)

#define address_family(address) ((address)->ss_family)

#define address4(address) ((struct sockaddr_in *)(address))
#define address6(address) ((struct sockaddr_in6 *)(address))
#define address_sa(address) ((struct sockaddr *)(address))

#define address4_ip(address) (address4(address)->sin_addr)
#define address6_ip(address) (address6(address)->sin6_addr)
#define address6_scope_id(address) (address4_ptr(address)->sin6_scope_id)

#define address_socklen(address) (((address)->ss_family == AF_INET) \
        ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6))

#define address4_is_local(address) \
    ((htonl((address4_ip(address)).s_addr) & 0xFF000000) == 0x7F000000)

#define address6_is_local(address) (IN6_IS_ADDR_LOOPBACK(address6(address)))

#define address_is_local(address) ((address)->ss_family == AF_INET) \
        ? address4_is_local(address) : address6_is_local(address)

int address_from_ip_port(address_t * address, int family, ip_address_t * addr, uint16_t port);

#define ADDRESS4(ip, port) (*(address_t*) &((struct sockaddr_in) { \
    .sin_family = AF_INET,                                      \
    .sin_port = htons(port),                                    \
    .sin_addr.s_addr = htonl(ip),                               \
}))

#define ADDRESS4_LOCALHOST(port) ADDRESS4(INADDR_LOOPBACK, (port))

/**
 * @brief Helper function to avoid macro expansion in c++ tests. Wrapper around 'ADDRESS4_LOCALHOST()'.
 *
 * @param port
 * @return address_t
 */
address_t _ADDRESS4_LOCALHOST(uint16_t port);

#define ADDRESS4_ANY(port) ADDRESS4(INADDR_ANY, (port))

#define ADDRESS6(ip, port) (*(address_t*) &((struct sockaddr_in6) {\
    .sin6_family = AF_INET6,                                    \
    .sin6_port = htons(port),                                   \
    .sin6_addr = IN6ADDR_ANY_INIT,                              \
    .sin6_scope_id = 0,                                         \
}))

#define ADDRESS6_ANY(port) ADDRESS6(IN6ADDR_ANY_INIT, port)

#define ADDRESS_ANY(family, port) ((family == AF_INET)          \
        ? ADDRESS4_ANY(port)                                    \
        : ADDRESS6_ANY(port))

extern const char * _address_family_str[];

#define address_family_str(address) (_address_family_str[address_family(address)])

#define address4_empty(address) (address4_ip(address).s_addr == 0)
#define address6_empty(address) (memcmp(address6_ip(address).s6_addr, &in6addr_any, sizeof(struct in6_addr)) == 0)
#define address_empty(address) (address_family(address) == AF_INET ? address4_empty(address) : address6_empty(address))

/**
 * @brief Return the string representation and the port of the IP address provided.
 *
 * @param[in] address Address to obtain the string representation from.
 * @param[in, out] buffer String to store the string representation of the address. It contains "N/A" in case of failure (see return value).
 * @param[in, out] port Integer to store the the port. It contains -1 in case of failure (see return value). If NULL, it will not be used to store the port.
 * @return int 0 if success, failure otherwise.
 */

int address_to_string(const address_t *address, char *buffer, int *port);

#endif /* HICNLIGHT_ADDRESS_H */
