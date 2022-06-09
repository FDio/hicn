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

#ifndef __HICN_FACE_FLAGS_H__
#define __HICN_FACE_FLAGS_H__

/* Flags */
/* A face is complete and it stores all the information. A iface lacks of the
   adj index, therefore sending a packet through a iface require a lookup in
   the FIB. */
#define foreach_face_flag                                                     \
  _ (0, FACE, "face")                                                         \
  _ (1, IFACE, "iface")                                                       \
  _ (2, APPFACE_PROD, "face is consumer face")                                \
  _ (3, APPFACE_CONS, "face is consumer face")                                \
  _ (4, DELETED, "face is deleted")                                           \
  _ (5, UDP, "face is udp")

enum
{
  HICN_FACE_FLAGS_DEFAULT = 0,
#define _(a, b, c) HICN_FACE_FLAGS_##b = (1 << a),
  foreach_face_flag
#undef _
};

#endif /* __HICN_FACE_FLAGS_H__ */