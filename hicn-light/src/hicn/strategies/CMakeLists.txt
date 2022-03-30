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

list(APPEND HEADER_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/load_balancer.h
  ${CMAKE_CURRENT_SOURCE_DIR}/low_latency.h
  ${CMAKE_CURRENT_SOURCE_DIR}/random.h
  ${CMAKE_CURRENT_SOURCE_DIR}/replication.h
  ${CMAKE_CURRENT_SOURCE_DIR}/best_path.h
  ${CMAKE_CURRENT_SOURCE_DIR}/local_prefixes.h
  ${CMAKE_CURRENT_SOURCE_DIR}/probe_generator.h
)

list(APPEND SOURCE_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/load_balancer.c
  ${CMAKE_CURRENT_SOURCE_DIR}/low_latency.c
  ${CMAKE_CURRENT_SOURCE_DIR}/random.c
  ${CMAKE_CURRENT_SOURCE_DIR}/replication.c
  ${CMAKE_CURRENT_SOURCE_DIR}/best_path.c
  ${CMAKE_CURRENT_SOURCE_DIR}/local_prefixes.c
  ${CMAKE_CURRENT_SOURCE_DIR}/probe_generator.c
)

set(SOURCE_FILES ${SOURCE_FILES} PARENT_SCOPE)
set(HEADER_FILES ${HEADER_FILES} PARENT_SCOPE)
