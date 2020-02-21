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

cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

list(APPEND SOURCE_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/rtc_socket_producer.cc
)

list(APPEND HEADER_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/socket.h
  ${CMAKE_CURRENT_SOURCE_DIR}/rtc_socket_producer.h
  ${CMAKE_CURRENT_SOURCE_DIR}/socket_producer.h
  ${CMAKE_CURRENT_SOURCE_DIR}/socket_consumer.h
)

if (${OPENSSL_VERSION} VERSION_EQUAL "1.1.1a" OR ${OPENSSL_VERSION} VERSION_GREATER "1.1.1a")
  list(APPEND SOURCE_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/tls_socket_producer.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/tls_rtc_socket_producer.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/p2psecure_socket_producer.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/tls_socket_consumer.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/p2psecure_socket_consumer.cc
  )

  list(APPEND HEADER_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/tls_socket_producer.h
    ${CMAKE_CURRENT_SOURCE_DIR}/tls_rtc_socket_producer.h
    ${CMAKE_CURRENT_SOURCE_DIR}/p2psecure_socket_producer.h
    ${CMAKE_CURRENT_SOURCE_DIR}/tls_socket_consumer.h
    ${CMAKE_CURRENT_SOURCE_DIR}/p2psecure_socket_consumer.h
  )
endif()

set(HEADER_FILES ${HEADER_FILES} PARENT_SCOPE)
set(SOURCE_FILES ${SOURCE_FILES} PARENT_SCOPE)
