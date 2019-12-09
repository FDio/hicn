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
 * \file address_pair.h
 * \brief Address pair
 */

#ifndef HICN_ADDRESS_PAIR_H
#define HICN_ADDRESS_PAIR_H

#include <hicn/base/address.h>
#include <hicn/util/ip_address.h>

typedef struct {
    address_t local;
    address_t remote;
} address_pair_t;

int address_pair_from_ip_port(address_pair_t * pair, int family,
        ip_address_t * local_addr, uint16_t local_port,
        ip_address_t * remote_addr, uint16_t remote_port);

#define address_pair_local(pair) (&(pair)->local)
#define address_pair_remote(pair) (&(pair)->remote)

#define address_pair_local_family(pair) \
    (address_family(address_pair_local(pair)))
#define address_pair_remote_family(pair) \
    (address_family(address_pair_remote(pair)))
#define address_pair_family(pair) address_pair_local_family(pair)

#define address_pair_valid(pair) \
    (address_pair_local_family(pair) == address_pair_remote_family(pair))

#endif /* HICN_ADDRESS_PAIR_H */
