# Copyright (c) 2021 Cisco and/or its affiliates.
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


list(APPEND HICNLIGHT_MODULE_SOURCE_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/hicn_light_api.c
)

build_module(hicnlightctrl_module
    SHARED
    SOURCES ${HICNLIGHT_MODULE_SOURCE_FILES}
    DEPENDS ${DEPENDENCIES}
    COMPONENT ${LIBHICNCTRL_COMPONENT}
    INCLUDE_DIRS ${INCLUDE_DIRS}
    DEFINITIONS ${COMPILER_DEFINITIONS}
    COMPILE_OPTIONS ${COMPILE_FLAGS}
)

if(BUILD_HICNPLUGIN AND ${CMAKE_SYSTEM_NAME} MATCHES "Linux")
  list(APPEND HICNLIGHT_PLUGIN_SOURCE_FILES
      ${CMAKE_CURRENT_SOURCE_DIR}/hicn_plugin_api.c
  )

  build_module(vppctrl_module
      SHARED
      SOURCES ${HICNLIGHT_PLUGIN_SOURCE_FILES}
      DEPENDS ${DEPENDENCIES}
      LINK_LIBRARIES ${HICNPLUGIN_LIBRARIES} ${SAFE_VAPI_LIBRARIES}
      COMPONENT ${LIBHICNCTRL_COMPONENT_MODULES}
      INCLUDE_DIRS ${INCLUDE_DIRS}
      DEFINITIONS ${COMPILER_DEFINITIONS}
      COMPILE_OPTIONS ${COMPILE_FLAGS}
      LINK_FLAGS "-Wl,-unresolved-symbols=ignore-in-shared-libs"
  )

endif()