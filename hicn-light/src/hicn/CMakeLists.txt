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

##############################################################
# Libraries to link
##############################################################
set(LIBRARIES
  PUBLIC ${HICN_LIBRARIES}
  PUBLIC ${LIBHICNCTRL_LIBRARIES}
  PRIVATE ${LIBEVENT_LIBRARIES}
  PRIVATE ${CMAKE_THREAD_LIBS_INIT}
)

if (UNIX)
  list(APPEND LIBRARIES
    m
  )
endif()


##############################################################
# Configuration file
##############################################################
configure_file(config.h.in hicn-light/config.h @ONLY)


##############################################################
# Compiler definitions
##############################################################
list(APPEND COMPILER_DEFINITIONS
  PRIVATE -DLIBRTA_DISABLE_VALIDATION
)

list(APPEND COMPILER_DEFINITIONS
#  "-DWITH_GRO"
#  "-DWITH_GSO"
#  "-DWITH_ZEROCOPY"
  PRIVATE "-DWITH_POLICY_STATS"
  PRIVATE "-DWITH_CLI"
#  "-DNDEBUG=1" # disable assertions
)

if (UNIX AND NOT APPLE)
  list(APPEND COMPILER_DEFINITIONS
    "-D_GNU_SOURCE" # batching support through struct mmsghdr
  )
endif()


##############################################################
# Compiler options
##############################################################
set(COMPILER_OPTIONS
  PRIVATE ${DEFAULT_COMPILER_OPTIONS}
  #PRIVATE "-Wno-address-of-packed-member"
)

##############################################################
# Sources
##############################################################
if (NOT DISABLE_EXECUTABLES)
  add_subdirectory(cli)
endif()

add_subdirectory(base)
add_subdirectory(config)
add_subdirectory(content_store)
add_subdirectory(core)
add_subdirectory(io)
add_subdirectory(platforms)
add_subdirectory(socket)
add_subdirectory(strategies)
add_subdirectory(utils)

list(APPEND TO_INSTALL_HEADER_FILES
  ${HEADER_FILES}
)

list(APPEND HEADER_FILES
  ${CMAKE_CURRENT_BINARY_DIR}/hicn-light/config.h
)


##############################################################
# Includes
##############################################################
list(APPEND HICN_LIGHT_INCLUDE_DIRS
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/..>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  PRIVATE
    ${LIBEVENT_INCLUDE_DIRS}
    ${WINDOWS_INCLUDE_DIRS}
)

list(APPEND TO_INSTALL_HEADER_FILES
  ${CMAKE_CURRENT_BINARY_DIR}/hicn-light/config.h
)


##############################################################
# Build type
##############################################################
set(LIB_BUILD_TYPE STATIC)
if (NOT ${CMAKE_SYSTEM_NAME} STREQUAL "Android")
  list(APPEND LIB_BUILD_TYPE
    "NO_DEV"
  )
endif()


##############################################################
# Build forwarder library
##############################################################
build_library(${LIBHICN_LIGHT}
  ${LIB_BUILD_TYPE}
  SOURCES ${SOURCE_FILES}
  INSTALL_HEADERS ${TO_INSTALL_HEADER_FILES}
  LINK_LIBRARIES ${LIBRARIES}
  DEPENDS ${DEPENDENCIES}
  COMPONENT ${HICN_LIGHT}
  INCLUDE_DIRS ${HICN_LIGHT_INCLUDE_DIRS}
  HEADER_ROOT_DIR hicn
  DEFINITIONS PUBLIC ${COMPILER_DEFINITIONS}
  COMPILE_OPTIONS ${COMPILER_OPTIONS}
)


##############################################################
# Build tests
##############################################################
if (BUILD_TESTS)
  add_subdirectory(test)
endif()
