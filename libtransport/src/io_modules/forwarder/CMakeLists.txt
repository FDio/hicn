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

list(APPEND MODULE_HEADER_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/connector.h
  ${CMAKE_CURRENT_SOURCE_DIR}/endpoint.h
  ${CMAKE_CURRENT_SOURCE_DIR}/errors.h
  ${CMAKE_CURRENT_SOURCE_DIR}/forwarder_module.h
  ${CMAKE_CURRENT_SOURCE_DIR}/forwarder.h
)

list(APPEND MODULE_SOURCE_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/errors.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/forwarder_module.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/forwarder.cc
)

build_module(forwarder_module
    SOURCES ${MODULE_SOURCE_FILES}
    DEPENDS ${DEPENDENCIES}
    COMPONENT ${LIBTRANSPORT_COMPONENT}-io-modules
    INCLUDE_DIRS ${LIBTRANSPORT_INTERNAL_INCLUDE_DIRS} ${Libhicn_INCLUDE_DIRS}
    DEFINITIONS ${COMPILER_DEFINITIONS}
    COMPILE_OPTIONS ${COMPILER_OPTIONS}
)
