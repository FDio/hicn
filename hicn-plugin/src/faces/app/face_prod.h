/*
 * Copyright (c) 2017-2020 Cisco and/or its affiliates.
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

#ifndef _FACE_PRODUCER_H_
#define _FACE_PRODUCER_H_

#include "../../cache_policies/cs_policy.h"
#include "../face.h"

/**
 * @file
 *
 * @brief Producer application face.
 *
 * A producer application face is built upon an ip face and identify a local
 * producer application (co-located with the forwarder) that acts as a producer. In the
 * current design an application face is either a face towards a consumer face
 * or towards a producer. The interface used by the producer application face is
 * assumed to be reserved only for hICN traffic (e.g.,  dedicated memif that
 * connects the applictation to the forwarder). Only one application face can be
 * assigned to an interface.
 *
 * To each producer application face it is assigned a portion of the CS. Every
 * data arriving to a producer application will be stored in the portion of the
 * CS assigned to the face. The eviction policy is defined in the
 * face. Available eviction faces are list in the /cache_policy folder.
 *
 * In the vlib graph a producer application face is directly connected to the
 * device-input node (with the node hicn-face-prod-input) and passes every packet to
 * the hicn-face-ip node.
 */

/**
 * @brief Producer application face state that refer to the hICN producer socket
 * created by the application.
 *
 */
typedef struct
{
  fib_prefix_t prefix;
} hicn_face_prod_state_t;

extern hicn_face_prod_state_t *face_state_vec;

#define DEFAULT_PROBING_PORT 3784

/**
 * @brief Add a new producer application face
 *
 * The method creates the internal ip face and the state specific to the
 * producer application face. This method setups a route in the FIB for the
 * producer's prefix.
 * @param prefix hicn prefix name assigned to the producer face
 * @param len length of the prefix
 * @param swif interface associated to the face
 * @param cs_reserved return the amount of cs assigned to the face
 * @param prod_addr address to assign to interface used by the appliction to
 * send data to the producer face
 */
int
hicn_face_prod_add (fib_prefix_t * prefix, u32 swif, u32 * cs_reserved,
		    ip46_address_t * prod_addr, hicn_face_id_t * faceid);

/**
 * @brief Delete an existing application face
 *
 * @param faceid id of the face to remove
 */
int hicn_face_prod_del (hicn_face_id_t faceid);

/**
 * @brief Set lru queue size for an app face
 *
 * @param face_id Id of the producer application face
 */
int hicn_face_prod_set_lru_max (hicn_face_id_t face_id, u32 * requested_size);

/**
 * @brief Format an application producer face
 *
 * @param s Pointer to a previous string. If null it will be initialize
 * @param args Array storing input values. Expected u32 face_id and u32 indent
 * @return String with the formatted face
 */
u8 *format_hicn_face_prod (u8 * s, va_list * args);


#endif /* _FACE_PROD_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
