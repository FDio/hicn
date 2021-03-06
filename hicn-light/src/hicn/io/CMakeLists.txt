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
  ${CMAKE_CURRENT_SOURCE_DIR}/addressPair.h
  ${CMAKE_CURRENT_SOURCE_DIR}/ioOperations.h
  ${CMAKE_CURRENT_SOURCE_DIR}/listener.h
  ${CMAKE_CURRENT_SOURCE_DIR}/listenerSet.h
  ${CMAKE_CURRENT_SOURCE_DIR}/tcpListener.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicnListener.h
  ${CMAKE_CURRENT_SOURCE_DIR}/udpTunnel.h
  ${CMAKE_CURRENT_SOURCE_DIR}/tcpTunnel.h
  ${CMAKE_CURRENT_SOURCE_DIR}/udpConnection.h
  ${CMAKE_CURRENT_SOURCE_DIR}/udpListener.h
  ${CMAKE_CURRENT_SOURCE_DIR}/streamConnection.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicnTunnel.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicnConnection.h
)

list(APPEND SOURCE_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/addressPair.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ioOperations.c
  ${CMAKE_CURRENT_SOURCE_DIR}/listenerSet.c
  ${CMAKE_CURRENT_SOURCE_DIR}/streamConnection.c
  ${CMAKE_CURRENT_SOURCE_DIR}/tcpListener.c
  ${CMAKE_CURRENT_SOURCE_DIR}/tcpTunnel.c
  ${CMAKE_CURRENT_SOURCE_DIR}/udpConnection.c
  ${CMAKE_CURRENT_SOURCE_DIR}/udpListener.c
  ${CMAKE_CURRENT_SOURCE_DIR}/udpTunnel.c
)

if("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
  list(APPEND SOURCE_FILES
    io/hicnTunnel.c
    io/hicnConnection.c
    io/hicnListener.c
  )
endif()

set(TO_INSTALL_HEADER_FILES
  ${TO_INSTALL_HEADER_FILES}
  ${HEADER_FILES}
  PARENT_SCOPE
)

set(SOURCE_FILES ${SOURCE_FILES} PARENT_SCOPE)
set(HEADER_FILES ${HEADER_FILES} PARENT_SCOPE)