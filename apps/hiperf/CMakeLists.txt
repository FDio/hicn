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

if (NOT DISABLE_EXECUTABLES)
  list(APPEND HIPERF_SRC
    ${CMAKE_CURRENT_SOURCE_DIR}/src/client.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/src/server.cc
  )

  list (APPEND HIPERF_LIBRARIES
    ${LIBTRANSPORT_LIBRARIES}
    ${CMAKE_THREAD_LIBS_INIT}
    ${WSOCK32_LIBRARY}
    ${WS2_32_LIBRARY}
  )

  build_executable(hiperf
    SOURCES ${HIPERF_SRC}
    LINK_LIBRARIES ${HIPERF_LIBRARIES}
    INCLUDE_DIRS
      ${CMAKE_CURRENT_SOURCE_DIR}/src
      ${LIBTRANSPORT_INCLUDE_DIRS}
    DEPENDS ${DEPENDENCIES}
    COMPONENT ${HICN_APPS}
    LINK_FLAGS ${LINK_FLAGS}
  )
endif()