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
set(CMAKE_CXX_STANDARD 14)

project(apps)

set(CMAKE_MODULE_PATH
  ${CMAKE_MODULE_PATH}
  "${CMAKE_CURRENT_SOURCE_DIR}/../cmake/Modules"
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules"
)

include(BuildMacros)
include(WindowsMacros)

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
  find_package(Libtransport REQUIRED)
  include_directories(${LIBTRANSPORT_INCLUDE_DIRS})
  set(HICN_APPS hicn-apps)
else()
  set(LIBTRANSPORT_LIBRARIES ${LIBTRANSPORT_SHARED})
  list(APPEND DEPENDENCIES
    ${LIBTRANSPORT_LIBRARIES}
  )
endif()

set(SUFFIX "")
if (${LIBTRANSPORT_LIBRARIES} MATCHES ".*-memif.*")
  set(SUFFIX "-memif")
endif()

set(HICN_APPS "${HICN_APPS}${SUFFIX}")

list(APPEND LIBRARIES
  ${LIBTRANSPORT_LIBRARIES}
  ${CMAKE_THREAD_LIBS_INIT}
)

if (WIN32)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /wd4200 /wd4996")
endif ()

set(HIGET higet)
set(HTTP_SERVER hicn-http-sever)
set(HTTP_PROXY hicn-http-proxy)

add_subdirectory(http-server)
add_subdirectory(http-proxy)
add_subdirectory(higet)