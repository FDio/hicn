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

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
  find_package(Libhicnctrl ${HICN_CURRENT_VERSION} REQUIRED NO_MODULE)

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

list(APPEND MODULE_HEADER_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn_forwarder_module.h
)

list(APPEND MODULE_SOURCE_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn_forwarder_module.cc
)

build_module(hicnlight_module
    SHARED
    SOURCES ${MODULE_SOURCE_FILES}
    DEPENDS ${DEPENDENCIES}
    COMPONENT ${LIBTRANSPORT_COMPONENT}
    LINK_LIBRARIES PRIVATE ${LIBHICNCTRL_LIBRARIES}
    INCLUDE_DIRS
      PRIVATE
        ${LIBTRANSPORT_INTERNAL_INCLUDE_DIRS}
        ${Libhicn_INCLUDE_DIRS}
        ${Libhicnctrl_INCLUDE_DIRS}
    DEFINITIONS ${COMPILER_DEFINITIONS}
    COMPILE_OPTIONS ${COMPILER_OPTIONS}
)
