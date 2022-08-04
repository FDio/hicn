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
# Android case: no submodules
##############################################################
if (${CMAKE_SYSTEM_NAME} MATCHES Android OR ${CMAKE_SYSTEM_NAME} MATCHES iOS)
  list(APPEND SOURCE_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/hicn-light/hicn_forwarder_module.cc
  )

  list(APPEND HEADER_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/hicn-light/hicn_forwarder_module.h
  )

  if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    find_package(Libhicnctrl ${CURRENT_VERSION} REQUIRED NO_MODULE)

    if (DISABLE_SHARED_LIBRARIES)
      set(LIBTYPE static)
    else()
      set(LIBTYPE shared)
    endif()

    list(APPEND LIBHICNCTRL_LIBRARIES hicn::hicnctrl.${LIBTYPE})
  else()
    if (DISABLE_SHARED_LIBRARIES)
      if (WIN32)
        set(LIBHICNCTRL_LIBRARIES ${LIBHICNCTRL_STATIC})
      else ()
        set(LIBHICNCTRL_LIBRARIES ${LIBHICNCTRL_STATIC} log)
      endif ()
      list(APPEND DEPENDENCIES
        ${LIBHICNCTRL_STATIC}
      )
    else()
      set(LIBHICNCTRL_LIBRARIES ${LIBHICNCTRL_SHARED})
      list(APPEND DEPENDENCIES
        ${LIBHICNCTRL_SHARED}
      )
    endif()
  endif()

  list(APPEND LIBRARIES
    PRIVATE ${LIBHICNCTRL_LIBRARIES}
  )

  list(APPEND LIBTRANSPORT_INTERNAL_INCLUDE_DIRS
    PUBLIC
      $<BUILD_INTERFACE:${LIBHICNCTRL_INCLUDE_DIRS}>
  )

  set(SOURCE_FILES ${SOURCE_FILES} PARENT_SCOPE)
  set(HEADER_FILES ${HEADER_FILES} PARENT_SCOPE)
  set(LIBRARIES ${LIBRARIES} PARENT_SCOPE)
  set(LIBTRANSPORT_INTERNAL_INCLUDE_DIRS ${LIBTRANSPORT_INTERNAL_INCLUDE_DIRS} PARENT_SCOPE)
else()
##############################################################
# Compile submodules
##############################################################
  add_subdirectory(hicn-light)
  add_subdirectory(loopback)
  add_subdirectory(forwarder)

  if (__vpp__)
    add_subdirectory(memif)
  endif()
endif()
