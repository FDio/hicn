# Copyright (c) 2021-2022 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

list(APPEND HEADER_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/address.h
  ${CMAKE_CURRENT_SOURCE_DIR}/address_pair.h
  ${CMAKE_CURRENT_SOURCE_DIR}/connection.h
  ${CMAKE_CURRENT_SOURCE_DIR}/connection_vft.h
  ${CMAKE_CURRENT_SOURCE_DIR}/connection_table.h
  ${CMAKE_CURRENT_SOURCE_DIR}/content_store.h
  ${CMAKE_CURRENT_SOURCE_DIR}/fib_entry.h
  ${CMAKE_CURRENT_SOURCE_DIR}/fib.h
  ${CMAKE_CURRENT_SOURCE_DIR}/forwarder.h
  ${CMAKE_CURRENT_SOURCE_DIR}/listener.h
  ${CMAKE_CURRENT_SOURCE_DIR}/listener_table.h
  ${CMAKE_CURRENT_SOURCE_DIR}/listener_vft.h
  ${CMAKE_CURRENT_SOURCE_DIR}/msgbuf.h
  ${CMAKE_CURRENT_SOURCE_DIR}/msgbuf_pool.h
  ${CMAKE_CURRENT_SOURCE_DIR}/packet_cache.h
  ${CMAKE_CURRENT_SOURCE_DIR}/pit.h
  ${CMAKE_CURRENT_SOURCE_DIR}/policy_stats.h
  ${CMAKE_CURRENT_SOURCE_DIR}/strategy.h
  ${CMAKE_CURRENT_SOURCE_DIR}/strategy_vft.h
  ${CMAKE_CURRENT_SOURCE_DIR}/subscription.h
  ${CMAKE_CURRENT_SOURCE_DIR}/ticks.h

  # ${CMAKE_CURRENT_SOURCE_DIR}/system.h
  ${CMAKE_CURRENT_SOURCE_DIR}/mapme.h
  ${CMAKE_CURRENT_SOURCE_DIR}/wldr.h
  ${CMAKE_CURRENT_SOURCE_DIR}/nexthops.h
)

list(APPEND SOURCE_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/address.c
  ${CMAKE_CURRENT_SOURCE_DIR}/address_pair.c
  ${CMAKE_CURRENT_SOURCE_DIR}/connection.c
  ${CMAKE_CURRENT_SOURCE_DIR}/connection_table.c
  ${CMAKE_CURRENT_SOURCE_DIR}/connection_vft.c
  ${CMAKE_CURRENT_SOURCE_DIR}/content_store.c
  ${CMAKE_CURRENT_SOURCE_DIR}/fib.c
  ${CMAKE_CURRENT_SOURCE_DIR}/fib_entry.c
  ${CMAKE_CURRENT_SOURCE_DIR}/forwarder.c
  ${CMAKE_CURRENT_SOURCE_DIR}/listener.c
  ${CMAKE_CURRENT_SOURCE_DIR}/listener_table.c
  ${CMAKE_CURRENT_SOURCE_DIR}/listener_vft.c
  ${CMAKE_CURRENT_SOURCE_DIR}/mapme.c
  ${CMAKE_CURRENT_SOURCE_DIR}/msgbuf.c
  ${CMAKE_CURRENT_SOURCE_DIR}/msgbuf_pool.c
  ${CMAKE_CURRENT_SOURCE_DIR}/nexthops.c
  ${CMAKE_CURRENT_SOURCE_DIR}/packet_cache.c
  ${CMAKE_CURRENT_SOURCE_DIR}/pit.c
  ${CMAKE_CURRENT_SOURCE_DIR}/policy_stats.c
  ${CMAKE_CURRENT_SOURCE_DIR}/strategy.c
  ${CMAKE_CURRENT_SOURCE_DIR}/strategy_vft.c
  ${CMAKE_CURRENT_SOURCE_DIR}/subscription.c
  ${CMAKE_CURRENT_SOURCE_DIR}/wldr.c
)

set(SOURCE_FILES ${SOURCE_FILES} PARENT_SCOPE)
set(HEADER_FILES ${HEADER_FILES} PARENT_SCOPE)
