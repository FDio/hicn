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
# Source files
##############################################################
add_subdirectory(core)
add_subdirectory(interfaces)
add_subdirectory(protocols)
add_subdirectory(auth)
add_subdirectory(implementation)
add_subdirectory(utils)
add_subdirectory(http)


##############################################################
# Libraries to link
##############################################################
set(LIBRARIES
  PRIVATE ${HICN_LIBRARIES}
  PRIVATE ${CMAKE_THREAD_LIBS_INIT}
  PRIVATE ${CMAKE_DL_LIBS}
  PRIVATE ${OPENSSL_LIBRARIES}
  PRIVATE ${LIBCONFIG_CPP_LIBRARIES}
  PRIVATE ${THIRD_PARTY_LIBRARIES}
)


##############################################################
# Include dirs
##############################################################
list(APPEND LIBTRANSPORT_INTERNAL_INCLUDE_DIRS
  PRIVATE
    ${CMAKE_THREADS_INCLUDE_DIRS}
    ${ASIO_INCLUDE_DIRS}
    ${WINDOWS_INCLUDE_DIRS}
    ${LIBCONFIG_CPP_INCLUDE_DIRS}
    ${THIRD_PARTY_INCLUDE_DIRS}
  PUBLIC
    ${ASIO_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
)

list(APPEND LIBTRANSPORT_INTERNAL_INCLUDE_DIRS
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/
  PUBLIC
    $<BUILD_INTERFACE:${Libhicntransport_INCLUDE_DIRS}>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)


##############################################################
# Dependencies
##############################################################
list(APPEND DEPENDENCIES
  ${THIRD_PARTY_DEPENDENCIES}
)

##############################################################
# Compiler definitions
##############################################################
list(APPEND COMPILER_DEFINITIONS
  PUBLIC "-DASIO_STANDALONE"
)

if (ENABLE_RELY)
  list(APPEND COMPILER_DEFINITIONS
    PRIVATE "-DENABLE_RELY=1"
  )
endif()


##############################################################
# Compiler options
##############################################################
list(APPEND COMPILER_OPTIONS
  ${DEFAULT_COMPILER_OPTIONS}
)

if (NOT WIN32)
  list(APPEND COMPILER_OPTIONS
    PRIVATE "-pthread"
  )
else ()
  list(APPEND COMPILER_OPTIONS
    PRIVATE "-/wd4200 -D_WIN32_WINDOWS=0x0400"
  )
  if (CMAKE_BUILD_TYPE EQUAL "RELEASE")
    list(APPEND COMPILER_OPTIONS
      PRIVATE "/NODEFAULTLIB:\"MSVCRTD\""
    )
  endif ()
endif ()

if (${CMAKE_SYSTEM_NAME} MATCHES "Android")
  list(APPEND COMPILER_OPTIONS
    PRIVATE "-stdlib=libc++"
    PRIVATE "-isystem"
    PRIVATE "-lm"
  )
endif()


##############################################################
# Configuration file
##############################################################
configure_file("config.h.in" "hicn/transport/config.h" @ONLY)
install(
  FILES ${CMAKE_CURRENT_BINARY_DIR}/hicn/transport/config.h
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/hicn/transport
  COMPONENT ${LIBTRANSPORT_COMPONENT}-dev
)

if (${CMAKE_SYSTEM_NAME} MATCHES Darwin OR ${CMAKE_SYSTEM_NAME} MATCHES Linux)
  install(
    FILES "transport.config"
    DESTINATION ${CMAKE_INSTALL_FULL_SYSCONFDIR}/hicn
    COMPONENT ${LIBTRANSPORT_COMPONENT}
  )
else ()
  install(
    FILES "transport.config"
    DESTINATION ${CMAKE_INSTALL_PREFIX}/etc/hicn
    COMPONENT ${LIBTRANSPORT_COMPONENT}
  )
endif()


##############################################################
# IO Modules
##############################################################
add_subdirectory(io_modules)


##############################################################
# Build type
##############################################################
set (BUILD_TYPES "STATIC")

if (NOT DISABLE_SHARED_LIBRARIES)
  list(APPEND BUILD_TYPES
    "SHARED"
  )
endif()


##############################################################
# Build library
##############################################################
build_library(${LIBTRANSPORT}
  ${BUILD_TYPES}
  SOURCES ${SOURCE_FILES} ${HEADER_FILES}
  INSTALL_HEADERS ${LIBHICNTRANSPORT_TO_INSTALL_HEADER_FILES}
  LINK_LIBRARIES ${LIBRARIES}
  OBJECT_LIBRARIES ${THIRD_PARTY_OBJECT_LIBRARIES}
  DEPENDS ${DEPENDENCIES}
  COMPONENT ${LIBTRANSPORT_COMPONENT}
  INCLUDE_DIRS ${LIBTRANSPORT_INTERNAL_INCLUDE_DIRS}
  DEFINITIONS ${COMPILER_DEFINITIONS}
  VERSION ${CURRENT_VERSION}
  EXPORT_NAME ${LIBTRANSPORT_COMPONENT}
  COMPILE_OPTIONS ${COMPILER_OPTIONS}
)


##############################################################
# Unit tests
##############################################################
if (${BUILD_TESTS})
  add_subdirectory(test)
endif()


##############################################################
# Cmake config files
##############################################################
create_cmake_config (
  ${LIBTRANSPORT_COMPONENT}
  INCLUDE_DIRS ${Libhicntransport_INCLUDE_DIRS}
  VERSION ${CURRENT_VERSION}
  COMPONENT ${LIBTRANSPORT_COMPONENT}
  NAMESPACE hicn
)
