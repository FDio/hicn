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
  find_package(Libhicn ${CURRENT_VERSION} REQUIRED NO_MODULE)
  list(APPEND HICN_LIBRARIES hicn::hicn.${LIBTYPE})
else()
  set(LIBHICN_LIBRARIES ${LIBHICN_SHARED})
  list(APPEND DEPENDENCIES
    ${LIBHICN_LIBRARIES}
  )
endif()


##############################################################
# Source/Header files
##############################################################
set(HICN_PLUGIN_SOURCE_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn.c
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn_api.c
  ${CMAKE_CURRENT_SOURCE_DIR}/cli.c
  ${CMAKE_CURRENT_SOURCE_DIR}/hashtb.c
  ${CMAKE_CURRENT_SOURCE_DIR}/infra.c
  ${CMAKE_CURRENT_SOURCE_DIR}/mgmt.c
  ${CMAKE_CURRENT_SOURCE_DIR}/pcs.c
  ${CMAKE_CURRENT_SOURCE_DIR}/route.c
  ${CMAKE_CURRENT_SOURCE_DIR}/strategy_dpo_ctx.c
  ${CMAKE_CURRENT_SOURCE_DIR}/strategy_dpo_manager.c
  ${CMAKE_CURRENT_SOURCE_DIR}/strategy_node.c
  ${CMAKE_CURRENT_SOURCE_DIR}/interest_pcslookup_node.c
  ${CMAKE_CURRENT_SOURCE_DIR}/interest_hitpit_node.c
  ${CMAKE_CURRENT_SOURCE_DIR}/interest_hitcs_node.c
  ${CMAKE_CURRENT_SOURCE_DIR}/data_input_node.c
  ${CMAKE_CURRENT_SOURCE_DIR}/data_pcslookup_node.c
  ${CMAKE_CURRENT_SOURCE_DIR}/data_fwd_node.c
  ${CMAKE_CURRENT_SOURCE_DIR}/error.c
  ${CMAKE_CURRENT_SOURCE_DIR}/faces/face_cli.c
  ${CMAKE_CURRENT_SOURCE_DIR}/faces/face.c
  ${CMAKE_CURRENT_SOURCE_DIR}/faces/face_node.c
  ${CMAKE_CURRENT_SOURCE_DIR}/faces/iface_node.c
  ${CMAKE_CURRENT_SOURCE_DIR}/faces/app/address_mgr.c
  ${CMAKE_CURRENT_SOURCE_DIR}/faces/app/face_cons.c
  ${CMAKE_CURRENT_SOURCE_DIR}/faces/app/face_prod.c
  ${CMAKE_CURRENT_SOURCE_DIR}/faces/app/face_prod_node.c
  ${CMAKE_CURRENT_SOURCE_DIR}/faces/app/face_app_cli.c
  ${CMAKE_CURRENT_SOURCE_DIR}/pg.c
  ${CMAKE_CURRENT_SOURCE_DIR}/strategies/dpo_mw.c
  ${CMAKE_CURRENT_SOURCE_DIR}/strategies/strategy_mw.c
  ${CMAKE_CURRENT_SOURCE_DIR}/strategies/strategy_mw_cli.c
  ${CMAKE_CURRENT_SOURCE_DIR}/strategies/dpo_rr.c
  ${CMAKE_CURRENT_SOURCE_DIR}/strategies/strategy_rr.c
  ${CMAKE_CURRENT_SOURCE_DIR}/strategies/dpo_rp.c
  ${CMAKE_CURRENT_SOURCE_DIR}/strategies/strategy_rp.c
  ${CMAKE_CURRENT_SOURCE_DIR}/cache_policies/cs_lru.c
  ${CMAKE_CURRENT_SOURCE_DIR}/mapme_ack_node.c
  ${CMAKE_CURRENT_SOURCE_DIR}/mapme_ctrl_node.c
  ${CMAKE_CURRENT_SOURCE_DIR}/mapme_eventmgr.c
  ${CMAKE_CURRENT_SOURCE_DIR}/udp_tunnels/udp_decap_node.c
  ${CMAKE_CURRENT_SOURCE_DIR}/udp_tunnels/udp_tunnel.c
)

set(HICN_PLUGIN_HEADER_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn_all_api_h.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn_logging.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hashtb.h
  ${CMAKE_CURRENT_SOURCE_DIR}/mgmt.h
  ${CMAKE_CURRENT_SOURCE_DIR}/params.h
  ${CMAKE_CURRENT_SOURCE_DIR}/pcs.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn_api.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn.h
  ${CMAKE_CURRENT_SOURCE_DIR}/state.h
  ${CMAKE_CURRENT_SOURCE_DIR}/infra.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn_msg_enum.h
  ${CMAKE_CURRENT_SOURCE_DIR}/parser.h
  ${CMAKE_CURRENT_SOURCE_DIR}/route.h
  ${CMAKE_CURRENT_SOURCE_DIR}/strategy_dpo_ctx.h
  ${CMAKE_CURRENT_SOURCE_DIR}/strategy_dpo_manager.h
  ${CMAKE_CURRENT_SOURCE_DIR}/strategy.h
  ${CMAKE_CURRENT_SOURCE_DIR}/interest_pcslookup.h
  ${CMAKE_CURRENT_SOURCE_DIR}/interest_hitpit.h
  ${CMAKE_CURRENT_SOURCE_DIR}/interest_hitcs.h
  ${CMAKE_CURRENT_SOURCE_DIR}/data_pcslookup.h
  ${CMAKE_CURRENT_SOURCE_DIR}/data_fwd.h
  ${CMAKE_CURRENT_SOURCE_DIR}/error.h
  ${CMAKE_CURRENT_SOURCE_DIR}/face_db.h
  ${CMAKE_CURRENT_SOURCE_DIR}/faces/face.h
  ${CMAKE_CURRENT_SOURCE_DIR}/faces/face_node.h
  ${CMAKE_CURRENT_SOURCE_DIR}/faces/iface_node.h
  ${CMAKE_CURRENT_SOURCE_DIR}/faces/inlines.h
  ${CMAKE_CURRENT_SOURCE_DIR}/faces/face_dpo.h
  ${CMAKE_CURRENT_SOURCE_DIR}/faces/app/address_mgr.h
  ${CMAKE_CURRENT_SOURCE_DIR}/faces/app/face_cons.h
  ${CMAKE_CURRENT_SOURCE_DIR}/faces/app/face_prod.h
  ${CMAKE_CURRENT_SOURCE_DIR}/pg.h
  ${CMAKE_CURRENT_SOURCE_DIR}/strategies/dpo_mw.h
  ${CMAKE_CURRENT_SOURCE_DIR}/strategies/strategy_mw.h
  ${CMAKE_CURRENT_SOURCE_DIR}/strategies/dpo_rr.h
  ${CMAKE_CURRENT_SOURCE_DIR}/strategies/strategy_rr.h
  ${CMAKE_CURRENT_SOURCE_DIR}/strategies/dpo_rp.h
  ${CMAKE_CURRENT_SOURCE_DIR}/strategies/strategy_rp.h
  ${CMAKE_CURRENT_SOURCE_DIR}/cache_policies/cs_policy.h
  ${CMAKE_CURRENT_SOURCE_DIR}/cache_policies/cs_lru.h
  ${CMAKE_CURRENT_SOURCE_DIR}/mapme.h
  ${CMAKE_CURRENT_SOURCE_DIR}/mapme_ack.h
  ${CMAKE_CURRENT_SOURCE_DIR}/mapme_ctrl.h
  ${CMAKE_CURRENT_SOURCE_DIR}/mapme_eventmgr.h
  ${CMAKE_CURRENT_SOURCE_DIR}/udp_tunnels/udp_tunnel.h
)

set(HICN_API_TEST_SOURCE_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn_api_test.c
  ${CMAKE_CURRENT_SOURCE_DIR}/error.c
)

set(HICN_API_HEADER_FILES
  ${HICNPLUGIN_TO_INSTALL_HEADER_FILES}
)

set(HICN_API_GENERATED_FILES
  ${PROJECT_BINARY_DIR}/vpp_plugins/hicn/hicn.api.h
  ${PROJECT_BINARY_DIR}/vpp_plugins/hicn/hicn.api_types.h
  ${PROJECT_BINARY_DIR}/vpp_plugins/hicn/hicn.api_enum.h
)

set(HICN_VAPI_GENERATED_FILES
  ${PROJECT_BINARY_DIR}/vapi/hicn.api.vapi.h
  ${PROJECT_BINARY_DIR}/vapi/hicn.api.vapi.hpp
)


##############################################################
# Assume VPP is installed in standard location
##############################################################
if (NOT VPP_HOME)
  set(VPP_HOME /usr)
endif()


##############################################################
# RPath
##############################################################
SET(HICN_INSTALL_PREFIX
  ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}
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
set(COMPILE_DEFINITIONS
  "-DHICN_VPP_PLUGIN=1"
)

if (${CMAKE_BUILD_TYPE} MATCHES "Debug")
  list(APPEND COMPILE_DEFINITIONS
    "-DHICN_DDEBUG"
    "-DCLIB_DEBUG"
  )
endif()


##############################################################
# VPP API Generation
##############################################################
file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/vapi)
file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/vpp_plugins/hicn)

execute_process(
  COMMAND ${VPP_HOME}/bin/vppapigen --includedir ${VPP_HOME}/include --input ${CMAKE_CURRENT_SOURCE_DIR}/hicn.api --output ${PROJECT_BINARY_DIR}/vpp_plugins/hicn/hicn.api.h --outputdir ${PROJECT_BINARY_DIR}/vpp_plugins/hicn/
  COMMAND ${VPP_HOME}/bin/vppapigen JSON --includedir ${VPP_HOME}/include --input ${CMAKE_CURRENT_SOURCE_DIR}/hicn.api --output ${PROJECT_BINARY_DIR}/vapi/hicn.api.json --outputdir ${PROJECT_BINARY_DIR}/vapi/
)
execute_process(
  COMMAND ${VPP_HOME}/bin/vapi_c_gen.py ${PROJECT_BINARY_DIR}/vapi/hicn.api.json
  COMMAND ${VPP_HOME}/bin/vapi_cpp_gen.py ${PROJECT_BINARY_DIR}/vapi/hicn.api.json
)


##############################################################
# Include directories
##############################################################
set(HICN_PLUGIN_INCLUDE_DIRS_INTERNAL
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${VPP_INCLUDE_DIR}
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_BINARY_DIR}>
    $<BUILD_INTERFACE:${HICNPLUGIN_INCLUDE_DIRS}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)


##############################################################
# Build hicn plugins for VPP
##############################################################
build_module(${HICNPLUGIN}
  SOURCES ${HICN_PLUGIN_SOURCE_FILES}
  INSTALL_HEADERS ${HICN_API_HEADER_FILES} ${HICN_API_GENERATED_FILES}
  LINK_LIBRARIES PRIVATE ${LIBHICN_LIBRARIES}
  DEPENDS ${DEPENDENCIES}
  COMPONENT ${HICN_PLUGIN}
  INCLUDE_DIRS ${HICN_PLUGIN_INCLUDE_DIRS_INTERNAL}
  HEADER_ROOT_DIR "vpp_plugins"
  LIBRARY_ROOT_DIR "vpp_plugins"
  DEFINITIONS PUBLIC ${COMPILE_DEFINITIONS}
  COMPILE_OPTIONS ${COMPILER_OPTIONS}
  INSTALL_RPATH "${VPP_INSTALL_PLUGIN}:${HICN_INSTALL_PREFIX}:${VPP_HOME}/lib"
)

build_module(${HICN_API_TEST_PLUGIN}
  SOURCES ${HICN_API_TEST_SOURCE_FILES}
  INSTALL_HEADERS ${HICN_VAPI_GENERATED_FILES}
  COMPONENT ${HICN_PLUGIN}
  INCLUDE_DIRS ${HICN_PLUGIN_INCLUDE_DIRS_INTERNAL}
  HEADER_ROOT_DIR "vapi"
  LIBRARY_ROOT_DIR "vpp_api_test_plugins"
  DEFINITIONS PUBLIC ${COMPILE_DEFINITIONS}
  COMPILE_OPTIONS ${COMPILER_OPTIONS}
  INSTALL_RPATH "${VPP_INSTALL_PLUGIN}:${HICN_INSTALL_PREFIX}:${VPP_HOME}/lib"
)
