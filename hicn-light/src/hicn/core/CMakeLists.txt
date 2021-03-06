# Copyright (c) 2017-2019 Cisco and/or its affiliates.
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
  ${CMAKE_CURRENT_SOURCE_DIR}/connectionManager.h
  ${CMAKE_CURRENT_SOURCE_DIR}/connectionState.h
  ${CMAKE_CURRENT_SOURCE_DIR}/ticks.h
  ${CMAKE_CURRENT_SOURCE_DIR}/connectionList.h
  ${CMAKE_CURRENT_SOURCE_DIR}/connectionTable.h
  ${CMAKE_CURRENT_SOURCE_DIR}/connection.h
  ${CMAKE_CURRENT_SOURCE_DIR}/forwarder.h
  ${CMAKE_CURRENT_SOURCE_DIR}/logger.h
  ${CMAKE_CURRENT_SOURCE_DIR}/dispatcher.h
  ${CMAKE_CURRENT_SOURCE_DIR}/message.h
  ${CMAKE_CURRENT_SOURCE_DIR}/messagePacketType.h
  ${CMAKE_CURRENT_SOURCE_DIR}/numberSet.h
  ${CMAKE_CURRENT_SOURCE_DIR}/streamBuffer.h
  ${CMAKE_CURRENT_SOURCE_DIR}/system.h
  ${CMAKE_CURRENT_SOURCE_DIR}/mapme.h
  ${CMAKE_CURRENT_SOURCE_DIR}/wldr.h
  ${CMAKE_CURRENT_SOURCE_DIR}/messageHandler.h
  ${CMAKE_CURRENT_SOURCE_DIR}/nameBitvector.h
  ${CMAKE_CURRENT_SOURCE_DIR}/name.h
)

list(APPEND SOURCE_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/connection.c
  ${CMAKE_CURRENT_SOURCE_DIR}/connectionList.c
  ${CMAKE_CURRENT_SOURCE_DIR}/connectionManager.c
  ${CMAKE_CURRENT_SOURCE_DIR}/connectionTable.c
  ${CMAKE_CURRENT_SOURCE_DIR}/dispatcher.c
  ${CMAKE_CURRENT_SOURCE_DIR}/forwarder.c
  ${CMAKE_CURRENT_SOURCE_DIR}/logger.c
  ${CMAKE_CURRENT_SOURCE_DIR}/message.c
  ${CMAKE_CURRENT_SOURCE_DIR}/numberSet.c
  ${CMAKE_CURRENT_SOURCE_DIR}/streamBuffer.c
  ${CMAKE_CURRENT_SOURCE_DIR}/mapme.c
  ${CMAKE_CURRENT_SOURCE_DIR}/wldr.c
  ${CMAKE_CURRENT_SOURCE_DIR}/nameBitvector.c
  ${CMAKE_CURRENT_SOURCE_DIR}/name.c
)

set(SOURCE_FILES ${SOURCE_FILES} PARENT_SCOPE)
set(HEADER_FILES ${HEADER_FILES} PARENT_SCOPE)

set(TO_INSTALL_HEADER_FILES
  ${TO_INSTALL_HEADER_FILES}
  ${HEADER_FILES}
  PARENT_SCOPE
)
