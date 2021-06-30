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

#ifndef _ADDRESS_MGR_H_
#define _ADDRESS_MGR_H_

/**
 * @file
 *
 * @brief Address manager.
 *
 * Address manager that maintains a pool of ip4 and ip6 addresses to assign to
 * an interface.
 */

#define ADDR_MGR_IP4_LEN      32
#define ADDR_MGR_IP4_CONS_LEN 31
#define ADDR_MGR_IP6_LEN      128
#define ADDR_MGR_IP6_CONS_LEN 127

/**
 * @brief Get two consecutive IP v4 addresses from the same /31 subnet
 *
 * @param addr1 first ip address with the least significant bit set to 0
 * @param addr2 second ip address with the least significant bit set to 1
 */
void get_two_ip4_addresses (ip4_address_t *addr1, ip4_address_t *addr2);

/**
 * @brief Get two consecutive IP v6 addresses from the same /126 subnet
 *
 * @param addr1 first ip address with the least significant bit set to 0
 * @param addr2 second ip address with the least significant bit set to 1
 */
void get_two_ip6_addresses (ip6_address_t *addr1, ip6_address_t *addr2);

/**
 * @brief Get one IP v4 address
 *
 * @return ip address
 */
ip4_address_t get_ip4_address (void);

/**
 * @brief Get one IP v6 address
 *
 * @return ip address
 */
ip6_address_t get_ip6_address (void);

/**
 * @brief Init the address manager
 */
void address_mgr_init (void);

#endif /* _ADDRESS_MGR_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
