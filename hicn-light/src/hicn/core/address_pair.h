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
 * \file address_pair.h
 * \brief Address pair
 */

#ifndef HICNLIGHT_ADDRESS_PAIR_H
#define HICNLIGHT_ADDRESS_PAIR_H

#include <hicn/util/ip_address.h>

#include "address.h"

typedef struct {
  address_t local;
  address_t remote;
} address_pair_t;

/**
 * @brief Create an address pair starting from local and remote addresses.
 *
 * @param local The local address to use in the pair
 * @param remote The remote address to use in the pair
 * @return address_pair_t The address pair created
 */
address_pair_t address_pair_factory(address_t local, address_t remote);

int address_pair_from_ip_port(address_pair_t* pair, int family,
                              hicn_ip_address_t* local_addr,
                              uint16_t local_port,
                              hicn_ip_address_t* remote_addr,
                              uint16_t remote_port);

static inline int address_pair_equals(const address_pair_t* pair1,
                                      const address_pair_t* pair2) {
  return address_equals(&pair1->local, &pair2->local) &&
         address_equals(&pair1->remote, &pair2->remote);
}

#define address_pair_get_local(pair) (&(pair)->local)
#define address_pair_get_remote(pair) (&(pair)->remote)

#define address_pair_get_local_family(pair) \
  (address_family(address_pair_get_local(pair)))
#define address_pair_get_remote_family(pair) \
  (address_family(address_pair_get_remote(pair)))
#define address_pair_get_family(pair) address_pair_get_local_family(pair)

#define address_pair_is_valid(pair) \
  (address_pair_get_local_family(pair) == address_pair_get_remote_family(pair))

#endif /* HICNLIGHT_ADDRESS_PAIR_H */
