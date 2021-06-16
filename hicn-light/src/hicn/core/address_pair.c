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
 * \file address_pair.c
 * \brief Implementation of Address pair
 */

#include "address_pair.h"

int
address_pair_from_ip_port(address_pair_t * pair, int family,
        ip_address_t * local_addr, uint16_t local_port,
        ip_address_t * remote_addr, uint16_t remote_port)
{
  if (address_from_ip_port(&pair->local, family, local_addr, local_port) < 0)
    return -1;
  if (address_from_ip_port(&pair->remote, family, remote_addr, remote_port) < 0)
    return -1;
  return 0;
}
