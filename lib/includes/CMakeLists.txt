# Copyright (c) 2021-2022 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

##############################################################
# Public headers directory
##############################################################
set(Libhicn_INCLUDE_DIRS
  ${CMAKE_CURRENT_SOURCE_DIR}
  CACHE INTERNAL
  "" FORCE
)

set(LIBHICN_HEADER_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/hicn.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/base.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/common.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/error.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/face.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/mapme.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/name.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/packet.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/policy.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/strategy.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/validation.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/interest_manifest.h
  PARENT_SCOPE
)

set(LIBHICN_HEADER_FILES_UTIL
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/util/array.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/util/bitmap.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/util/hash.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/util/ip_address.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/util/khash.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/util/log.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/util/map.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/util/pool.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/util/ring.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/util/set.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/util/slab.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/util/sstrncpy.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/util/token.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/util/types.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/util/vector.h
  PARENT_SCOPE
)

set_property(GLOBAL PROPERTY LIBHICN_HEADER_FILES_UTIL_PROPERTY "${LIBHICN_HEADER_FILES_UTIL}")
