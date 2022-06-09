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
# Dependencies
##############################################################
find_package(HicnPlugin ${CURRENT_VERSION} REQUIRED)
find_package(Libsafevapi ${CURRENT_VERSION} REQUIRED NO_MODULE)


##############################################################
# Source files
##############################################################
list(APPEND SOURCE_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/vpp_hicn.c
)


##############################################################
# Include dirs
##############################################################
list(APPEND INCLUDE_DIRS
  ${COLLECTD_INCLUDE_DIRS}
  ${THIRD_PARTY_INCLUDE_DIRS}
  ${HICNPLUGIN_INCLUDE_DIRS}
  ${Libsafe_vapi_INCLUDE_DIRS}
  ${VPP_INCLUDE_DIRS}
)


##############################################################
# Libraries
##############################################################
list(APPEND LIBRARIES
  ${VPP_LIBRARY_VAPICLIENT}
  hicn::safevapi.shared
)


##############################################################
# Compiler options
##############################################################
list(APPEND COMPILER_OPTIONS
  ${DEFAULT_COMPILER_OPTIONS}
  ${COLLECTD_COMPILER_OPTIONS}
)


##############################################################
# Build library
##############################################################
build_library(${VPP_HICN_TELEMETRY}
  SHARED
  EMPTY_PREFIX
  SOURCES ${SOURCE_FILES}
  LINK_LIBRARIES ${LIBRARIES}
  INCLUDE_DIRS
    PRIVATE ${INCLUDE_DIRS}
  INSTALL_FULL_PATH_DIR ${COLLECTD_PLUGIN_DIR}
  COMPONENT ${COLLECTD_PLUGINS}
  DEPENDS ${DEPENDENCIES}
  COMPILE_OPTIONS ${COMPILER_OPTIONS}
)
