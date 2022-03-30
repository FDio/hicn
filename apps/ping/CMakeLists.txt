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

if (NOT DISABLE_EXECUTABLES)
##############################################################
# Compiler options
##############################################################
set(COMPILER_OPTIONS
  ${DEFAULT_COMPILER_OPTIONS}
)

##############################################################
# Libraries to link
##############################################################
  list (APPEND PING_LIBRARIES
    PRIVATE ${LIBHICN_LIBRARIES}
    PRIVATE ${LIBTRANSPORT_LIBRARIES}
    PRIVATE ${CMAKE_THREAD_LIBS_INIT}
    PRIVATE ${WSOCK32_LIBRARY}
    PRIVATE ${WS2_32_LIBRARY}
  )

##############################################################
# Build ping server
##############################################################
  build_executable(hicn-ping-server
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/ping_server.cc
    LINK_LIBRARIES ${PING_LIBRARIES}
    DEPENDS ${DEPENDENCIES}
    COMPONENT ${HICN_APPS}
    LINK_FLAGS ${LINK_FLAGS}
    COMPILE_OPTIONS ${COMPILER_OPTIONS}
  )

##############################################################
# Build ping client
##############################################################
  build_executable(hicn-ping-client
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/ping_client.cc
    LINK_LIBRARIES ${PING_LIBRARIES}
    DEPENDS ${DEPENDENCIES}
    COMPONENT ${HICN_APPS}
    LINK_FLAGS ${LINK_FLAGS}
    COMPILE_OPTIONS ${COMPILER_OPTIONS}
  )
endif ()