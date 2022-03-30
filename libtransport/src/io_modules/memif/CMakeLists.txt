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
# Dependencies and third party libs
##############################################################
find_package(Vpp ${VPP_DEFAULT_VERSION} EXACT REQUIRED)

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
  find_package(HicnPlugin ${CURRENT_VERSION} REQUIRED)
  find_package(SafeVapi ${CURRENT_VERSION} REQUIRED)
else()
  list(APPEND DEPENDENCIES
    ${SAFE_VAPI_SHARED}
  )
endif()

list(APPEND DEPENDENCIES
  ${MEMIF_THIRD_PARTY_DEPENDENCIES}
)

##############################################################
# Sources
##############################################################
list(APPEND MODULE_HEADER_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn_vapi.h
  ${CMAKE_CURRENT_SOURCE_DIR}/memif_connector.h
  ${CMAKE_CURRENT_SOURCE_DIR}/memif_vapi.h
  ${CMAKE_CURRENT_SOURCE_DIR}/vpp_forwarder_module.h
)

list(APPEND MODULE_SOURCE_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/hicn_vapi.c
    ${CMAKE_CURRENT_SOURCE_DIR}/memif_vapi.c
    ${CMAKE_CURRENT_SOURCE_DIR}/vpp_forwarder_module.cc
)

build_module(memif_module
    SOURCES ${MODULE_SOURCE_FILES}
    DEPENDS ${DEPENDENCIES}
    COMPONENT ${LIBTRANSPORT_COMPONENT}-io-modules
    OBJECT_LIBRARIES ${MEMIF_THIRD_PARTY_OBJECT_LIBRARIES}
    LINK_LIBRARIES PRIVATE ${HICN_LIBRARIES} ${SAFE_VAPI_LIBRARIES}
    INCLUDE_DIRS
      PUBLIC
        ${MEMIF_THIRD_PARTY_INCLUDE_DIRS}
        ${LIBTRANSPORT_INTERNAL_INCLUDE_DIRS}
        ${VPP_INCLUDE_DIRS}
        ${LIBMEMIF_INCLUDE_DIRS}
        ${SAFE_VAPI_INCLUDE_DIRS}
    DEFINITIONS ${COMPILER_DEFINITIONS}
    COMPILE_OPTIONS ${COMPILER_OPTIONS} ${MARCH_COMPILER_OPTIONS}
)
