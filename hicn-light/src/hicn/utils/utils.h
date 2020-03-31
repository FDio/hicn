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

#ifndef utils_h
#define utils_h

#include <hicn/config/controlState.h>
#include <hicn/utils/commands.h>

/**
 * Return true if string is purely an integer
 */
bool utils_IsNumber(const char *string);

/**
 * A symbolic name must be at least 1 character and must begin with an alpha.
 * The remainder must be an alphanum.
 */
bool utils_ValidateSymbolicName(const char *symbolic);

/**
 *Convert IPv4/IPv6 address from binary to text string. `uint8_t *ipAddress` has
 *to be a `in_addr_t * or `a struct in6_addr *.
 */
char *utils_CommandAddressToString(int family, ip_address_t *address,
        in_port_t *port);

/**
 *Given a command payload, it generates the header and send the request to the
 *deamon.
 */
struct iovec *utils_SendRequest(ControlState *state, command_id command,
                                void *payload, size_t payloadLen);

/**
 *Convert a IPv4/IPv6 address plus Netmask len from binary to text string in the
 *form [add]:[port]/[len].
 */
const char *utils_PrefixLenToString(int family, ip_address_t *address,
        uint8_t *prefixLen);

#endif
