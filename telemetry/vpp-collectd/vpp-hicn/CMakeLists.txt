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
# Check if building as subproject or as root project
##############################################################
if(${CMAKE_SOURCE_DIR}/vpp-collectd STREQUAL ${PROJECT_SOURCE_DIR})
  message (STATUS "not compiling in the same folder")
  find_package(HicnPlugin ${CURRENT_VERSION} REQUIRED)
  find_package(Vapisafe ${CURRENT_VERSION} REQUIRED)
else()
  message (STATUS "compiling in the same folder")
  list(APPEND DEPENDENCIES
    ${HICNPLUGIN_SHARED}
  )
endif()


##############################################################
# Sources
##############################################################
list(APPEND SOURCE_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/vpp_hicn.c
)

list(APPEND INCLUDE_DIRS
  ${COLLECTD_INCLUDE_DIRS}
  ${HICNPLUGIN_INCLUDE_DIRS}
  ${SAFE_VAPI_INCLUDE_DIRS}
  ${VPP_INCLUDE_DIRS}
  ${CMAKE_CURRENT_SOURCE_DIR}
  "${CMAKE_CURRENT_SOURCE_DIR}/../common"
)


##############################################################
# Libs
##############################################################
list(APPEND LIBRARIES
  ${VPP_LIBRARY_VAPICLIENT}
  ${SAFE_VAPI_LIBRARIES}
)


##############################################################
# Build library
##############################################################
build_library(vpp_hicn
  SOURCES ${SOURCE_FILES}
  LINK_LIBRARIES ${LIBRARIES}
  INCLUDE_DIRS ${INCLUDE_DIRS}
  INSTALL_FULL_PATH_DIR ${CMAKE_INSTALL_PREFIX}/lib/collectd
  COMPONENT "${COLLECTD_PLUGINS}"
  DEPENDS ${DEPENDENCIES}
  COMPILE_OPTIONS ${COMPILER_OPTIONS}
)
