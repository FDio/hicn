# Copyright (c) 2019 Cisco and/or its affiliates.
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

cmake_minimum_required(VERSION 3.2)

set(CMAKE_CXX_STANDARD 14)

find_package(CURL REQUIRED)
list(APPEND LIBRARIES
  ${CURL_LIBRARY}
)

set(LIB_SOURCE_FILES
  http-server/http_server.cc
  http-server/response.cc
  http-server/socket_response.cc
  http-server/icn_response.cc
  http-server/content.cc
  http-server/request.cc
  http-server/icn_request.cc
  http-server/socket_request.cc
  http-server/configuration.cc
  http-client/http_client_tcp.cc
  http-client/http_client_icn.cc
)

set(LIB_SERVER_HEADER_FILES
  http-server/http_server.h
  http-server/response.h
  http-server/common.h
  http-server/socket_response.h
  http-server/content.h
  http-server/request.h
  http-server/icn_request.h
  http-server/socket_request.h
  http-server/configuration.h
  http-server/icn_response.h
)

set(LIB_CLIENT_HEADER_FILES
  http-client/http_client_tcp.h
  http-client/http_client_icn.h
  http-client/http_client.h
)

set(APP_SOURCE_FILES
  http-server.cc
)

include_directories(
  ${CMAKE_BINARY_DIR}/apps/http-server
  http-server
  http-client
)

build_library(hicn-httpserver
  STATIC
  SOURCES ${LIB_SOURCE_FILES} ${LIB_SERVER_HEADER_FILES} ${LIB_CLIENT_HEADER_FILES}
  INSTALL_HEADERS ${HEADER_FILES}
  LINK_LIBRARIES ${LIBRARIES}
  DEPENDS ${DEPENDENCIES}
  COMPONENT lib${LIBTRANSPORT}
  INCLUDE_DIRS ${LIBTRANSPORT_INCLUDE_DIRS}
  INSTALL_ROOT_DIR hicn/transport
  DEFINITIONS ${COMPILER_DEFINITIONS}
)

build_executable(hicn-http-server
  SOURCES ${APP_SOURCE_FILES}
  LINK_LIBRARIES hicn-httpserver ${WSOCK32_LIBRARY} ${WS2_32_LIBRARY}
  DEPENDS hicn-httpserver
  COMPONENT ${HICN_APPS}
  DEFINITIONS ${COMPILER_DEFINITIONS}
)

