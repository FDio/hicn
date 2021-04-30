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


list(APPEND MODULE_HEADER_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn_forwarder_module.h
  ${CMAKE_CURRENT_SOURCE_DIR}/udp_socket_connector.h
)

list(APPEND MODULE_SOURCE_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/hicn_forwarder_module.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/udp_socket_connector.cc
)

# add_executable(hicnlight_module MACOSX_BUNDLE ${MODULE_SOURCE_FILES})  
# target_include_directories(hicnlight_module PRIVATE ${LIBTRANSPORT_INCLUDE_DIRS} ${LIBTRANSPORT_INTERNAL_INCLUDE_DIRS})          
# set_target_properties(hicnlight_module PROPERTIES
#     BUNDLE True
#     MACOSX_BUNDLE_GUI_IDENTIFIER my.domain.style.identifier.hicnlight_module
#     MACOSX_BUNDLE_BUNDLE_NAME hicnlight_module
#     MACOSX_BUNDLE_BUNDLE_VERSION "0.1"
#     MACOSX_BUNDLE_SHORT_VERSION_STRING "0.1"
#     # MACOSX_BUNDLE_INFO_PLIST ${CMAKE_SOURCE_DIR}/cmake/customtemplate.plist.in
# )
build_module(hicnlight_module
  SHARED
  SOURCES ${MODULE_SOURCE_FILES}
  DEPENDS ${DEPENDENCIES}
  COMPONENT lib${LIBTRANSPORT}
  INCLUDE_DIRS ${LIBTRANSPORT_INCLUDE_DIRS} ${LIBTRANSPORT_INTERNAL_INCLUDE_DIRS}
  # LIBRARY_ROOT_DIR "vpp_plugins"
  DEFINITIONS ${COMPILER_DEFINITIONS}
  COMPILE_OPTIONS ${COMPILE_FLAGS}
)

endif ()
