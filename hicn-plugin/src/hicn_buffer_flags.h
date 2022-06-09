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

#ifndef __HICN_BUFFER_FLAGS_H__
#define __HICN_BUFFER_FLAGS_H__

#define foreach_hicn_buffer_flag                                              \
  _ (0, NEW_FACE, "new face")                                                 \
  _ (1, PKT_LESS_TWO_CL, "packet is less that 2 cache lines length")          \
  _ (2, FROM_UDP4_TUNNEL, "packet is from udp4 tunnel")                       \
  _ (3, FROM_UDP6_TUNNEL, "packet is from udp6 tunnel")                       \
  _ (4, FROM_CS, "packet is from cs")                                         \
  _ (5, FROM_PG, "packet is from packet generator")

enum
{
  HICN_BUFFER_FLAGS_DEFAULT = 0,
#define _(a, b, c) HICN_BUFFER_FLAGS_##b = (1 << a),
  foreach_hicn_buffer_flag
#undef _
};

#endif /* __HICN_BUFFER_FLAGS_H__ */