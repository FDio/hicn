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
# Hicn Light NG Module
##############################################################
list(APPEND HICNLIGHT_MODULE_SOURCE_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn_light.c
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn_light/connection.c
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn_light/face.c
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn_light/listener.c
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn_light/route.c
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn_light/strategy.c
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn_light/subscription.c
)

list(APPEND HICNLIGHT_MODULE_HEADER_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn_light.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn_light/connection.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn_light/face.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn_light/listener.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn_light/route.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn_light/strategy.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn_light/subscription.h
  )

build_module(hicnlightctrl_module
  SOURCES ${HICNLIGHT_MODULE_SOURCE_FILES} ${HICNLIGHT_MODULE_HEADER_FILES}
  DEPENDS ${DEPENDENCIES}
  COMPONENT ${LIBHICNCTRL_COMPONENT}
  LINK_LIBRARIES PRIVATE ${HICN_LIBRARIES}
  INCLUDE_DIRS PRIVATE ${INCLUDE_DIRS}
  DEFINITIONS PRIVATE ${COMPILER_DEFINITIONS}
  COMPILE_OPTIONS PRIVATE ${COMPILE_FLAGS}
  COMPILE_OPTIONS ${COMPILER_OPTIONS}
)


##############################################################
# VPP Module
##############################################################
if(BUILD_HICNPLUGIN AND ${CMAKE_SYSTEM_NAME} MATCHES "Linux")
  if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    find_package(HicnPlugin ${CURRENT_VERSION} REQUIRED)
    find_package(Safevapi ${CURRENT_VERSION} REQUIRED)
  else()
    list(APPEND DEPENDENCIES
      ${SAFE_VAPI_SHARED}
    )
  endif()


  list(APPEND HICN_PLUGIN_SOURCE_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/hicn_plugin.c
    ${CMAKE_CURRENT_SOURCE_DIR}/hicn_plugin/listener.c
    ${CMAKE_CURRENT_SOURCE_DIR}/hicn_plugin/route.c
  )

  list(APPEND HICN_PLUGIN_HEADER_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/hicn_light/base.h
    ${CMAKE_CURRENT_SOURCE_DIR}/hicn_light/listener.h
    ${CMAKE_CURRENT_SOURCE_DIR}/hicn_light/route.h
  )

  ##############################################################
  # Compiler Options
  ##############################################################
  set(COMPILER_OPTIONS
    ${DEFAULT_COMPILER_OPTIONS}
    ${MARCH_COMPILER_OPTIONS}
    PRIVATE "-Wno-address-of-packed-member"
  )

  ##############################################################
  # Compiler Definitions
  ##############################################################
  list(APPEND COMPILER_DEFINITIONS
    PRIVATE "-DHICN_VPP_PLUGIN=1"
  )

  build_module(vppctrl_module
    SOURCES ${HICN_PLUGIN_SOURCE_FILES} ${HICN_PLUGIN_HEADER_FILES}
    DEPENDS ${DEPENDENCIES}
    LINK_LIBRARIES
      PRIVATE ${HICN_LIBRARIES}
      PRIVATE ${HICNPLUGIN_LIBRARIES}
      PRIVATE ${SAFE_VAPI_LIBRARIES}
    COMPONENT ${LIBHICNCTRL_COMPONENT_MODULES}
    INCLUDE_DIRS PRIVATE ${INCLUDE_DIRS}
    DEFINITIONS PRIVATE ${COMPILER_DEFINITIONS}
    COMPILE_OPTIONS ${COMPILER_OPTIONS}
  )
endif()
