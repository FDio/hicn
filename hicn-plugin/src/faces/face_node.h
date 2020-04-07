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

#ifndef __HICN_FACE_NODE_H__
#define __HICN_FACE_NODE_H__

#include <vlib/vlib.h>
#include <vnet/vnet.h>

extern vlib_node_registration_t hicn4_face_input_node;
extern vlib_node_registration_t hicn4_face_output_node;
extern vlib_node_registration_t hicn6_face_input_node;
extern vlib_node_registration_t hicn6_face_output_node;

#endif // __HICN_FACE_NODE_H__

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
