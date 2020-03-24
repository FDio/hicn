
# Copyright (c) 2019 Cisco
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
project(hicn_hs)

set(CMAKE_MODULE_PATH
  ${CMAKE_MODULE_PATH}
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules/"
)

option(BUILD_TESTS "Build the tests" OFF)

find_package(Libtransport)
find_package(Libhicn)

#########################################
# LOG LEVELS AVAILABLE
# VERBOSE
# DEBUG
# INFO
# WARN
# ERROR
# FATAL
# NONE
#
# Default: INFO
set(HICN_HS_LOG_LEVEL "INFO" CACHE STRING "Set log level")

if (NOT LIBTRANSPORT_FOUND)
  message (STATUS "Libtransport not found. hicn_hs plugin disabled.")
elseif (NOT HICN_FOUND)
  message (STATUS "libhicn not found. hicn_hs plugin disabled.")
else ()
  include_directories(
    ${CMAKE_BINARY_DIR}
    ${HICN_INCLUDE_DIRS}
    ${LIBTRANSPORT_INCLUDE_DIRS}
  )

  list(APPEND LIBRARIES
    ${HICN_LIBRARIES}
    ${LIBTRANSPORT_LIBRARIES}
  )

  list (APPEND SOURCE_FILES
    hicn_hs.c
    hicn_hs_input.c
    hicn_hs_prod_dpo.c
    hicn_hs_output.c
    hicn_hs_route.c
    error.c
    hicn_hs_cli.c
    cbr_proto.c
    test/hicn_hs_client.c
    test/hicn_hs_server.c
  )

  add_vpp_plugin(hicn_hs
    SOURCES ${SOURCE_FILES}
    LINK_LIBRARIES ${LIBRARIES}
  )

  message(STATUS "Building hicn_hs.")
endif()