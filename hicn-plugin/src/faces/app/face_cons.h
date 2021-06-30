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

#ifndef _FACE_CONSUMER_H_
#define _FACE_CONSUMER_H_

#include <vnet/vnet.h>
#include "../face.h"

/**
 * @file
 *
 * @brief Consumer application face.
 *
 * A consumer application face is built upon an ip face and identify a local
 * consumer application (co-located with the forwarder) that acts as a
 * consumer. The interface used by the consumer application face is
 * assumed to be reserved only for hICN traffic (e.g.,  dedicated memif that
 * connects the applictation to the forwarder). Only one application face can
 * be assigned to an interface.
 *
 * In the vlib graph a consumer application face directly connect the
 * device-input node to the hicn-vface-ip node.
 */

/**
 * @brief Add a new consumer application face
 *
 * The method creates the internal ip face and set the ip address to the
 * interface.
 * @param nh_addr4 ipv4 address to assign to interface used by the application
 * to send interest to the consumer face
 * @param nh_addr6 ipv6 address to assign to interface used by the application
 * to send interest to the consumer face
 * @param swif interface associated to the face
 */
int hicn_face_cons_add (ip4_address_t *nh_addr4, ip6_address_t *nh_addr6,
			u32 swif, hicn_face_id_t *faceid1,
			hicn_face_id_t *faceid2);

/**
 * @brief Delete an existing consumer application face
 *
 * @param face_id Id of the consumer application face
 */
int hicn_face_cons_del (hicn_face_id_t face_id);

/**
 * @brief Format an application consumer face
 *
 * @param s Pointer to a previous string. If null it will be initialize
 * @param args Array storing input values. Expected u32 face_id and u32 indent
 * @return String with the formatted face
 */
u8 *format_hicn_face_cons (u8 *s, va_list *args);

#endif /* _FACE_CONSUMER_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
