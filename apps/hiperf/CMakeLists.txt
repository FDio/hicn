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
# Source files
##############################################################
  list(APPEND HIPERF_SRC
    ${CMAKE_CURRENT_SOURCE_DIR}/src/client.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/src/server.cc
  )


##############################################################
# Libraries
##############################################################
  list (APPEND HIPERF_LIBRARIES
    PRIVATE ${LIBTRANSPORT_LIBRARIES}
    PRIVATE ${LIBHICNCTRL_LIBRARIES}
    PRIVATE ${LIBHICN_LIBRARIES}
    PRIVATE ${CMAKE_THREAD_LIBS_INIT}
    PRIVATE ${LIBCONFIG_CPP_LIBRARIES}
    PRIVATE ${WSOCK32_LIBRARY}
    PRIVATE ${WS2_32_LIBRARY}
  )

##############################################################
# Compiler options
##############################################################
  set(COMPILER_OPTIONS
    ${DEFAULT_COMPILER_OPTIONS}
  )


##############################################################
# Build hiperf
##############################################################
  build_executable(hiperf
    SOURCES ${HIPERF_SRC}
    LINK_LIBRARIES ${HIPERF_LIBRARIES}
    INCLUDE_DIRS
      PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
      PRIVATE ${LIBCONFIG_CPP_INCLUDE_DIRS}
      PRIVATE ${THIRD_PARTY_INCLUDE_DIRS} ${COMMON_INCLUDE_DIRS}
    DEPENDS ${DEPENDENCIES} ${THIRD_PARTY_DEPENDENCIES}
    COMPONENT ${HICN_APPS}
    LINK_FLAGS ${LINK_FLAGS}
    COMPILE_OPTIONS ${COMPILER_OPTIONS}
  )
endif()