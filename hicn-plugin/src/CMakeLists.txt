# Copyright (c) 2017-2020 Cisco and/or its affiliates.
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

# Dependencies
find_package(Vpp REQUIRED)

include_directories(${HICN_INCLUDE_DIRS} ${VPP_INCLUDE_DIR})

set(LIBHICN_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/src/mapme.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/src/name.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/src/ops.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/src/protocol/ah.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/src/protocol/icmp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/src/protocol/ipv4.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/src/protocol/ipv6.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/src/protocol/tcp.c
)

set(LIBHICN_HEADER_FILES_SRC
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/includes/hicn/hicn.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/includes/hicn/base.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/includes/hicn/common.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/includes/hicn/error.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/includes/hicn/header.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/includes/hicn/name.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/includes/hicn/protocol.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/includes/hicn/ops.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/includes/hicn/mapme.h
)

set(LIBHICN_HEADER_FILES_PROTOCOL
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/includes/hicn/protocol/ah.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/includes/hicn/protocol/icmp.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/includes/hicn/protocol/icmprd.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/includes/hicn/protocol/ipv4.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/includes/hicn/protocol/ipv6.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/includes/hicn/protocol/tcp.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/includes/hicn/protocol/udp.h
)

set(LIBHICN_HEADER_FILES_UTIL
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/includes/hicn/util/ip_address.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/includes/hicn/util/token.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/includes/hicn/util/types.h
)

set(HICN_PLUGIN_SOURCE_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/hicn.c
    ${CMAKE_CURRENT_SOURCE_DIR}/hicn_api.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cli.c
    ${CMAKE_CURRENT_SOURCE_DIR}/hashtb.c
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
    ${CMAKE_CURRENT_SOURCE_DIR}/cache_policies/cs_lru.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mapme_ack_node.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mapme_ctrl_node.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mapme_eventmgr.c
    ${CMAKE_CURRENT_SOURCE_DIR}/udp_tunnels/udp_decap_node.c
    ${CMAKE_CURRENT_SOURCE_DIR}/udp_tunnels/udp_tunnel.c
)

set(HICN_PLUGIN_HEADER_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/hicn_all_api_h.h
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
    ${CMAKE_CURRENT_SOURCE_DIR}/error.c)

set(HICN_API_HEADER_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/hicn_msg_enum.h
    ${CMAKE_CURRENT_SOURCE_DIR}/hicn_all_api_h.h
    ${CMAKE_CURRENT_SOURCE_DIR}/hicn_api.h
    ${CMAKE_CURRENT_SOURCE_DIR}/error.h)

set(HICN_API_GENERATED_FILES
    ${PROJECT_BINARY_DIR}/vpp_plugins/hicn/hicn.api.h
    ${PROJECT_BINARY_DIR}/vpp_plugins/hicn/hicn.api_types.h
    ${PROJECT_BINARY_DIR}/vpp_plugins/hicn/hicn.api_enum.h
)

set(HICN_VAPI_GENERATED_FILES
    ${PROJECT_BINARY_DIR}/vapi/hicn.api.vapi.h
    ${PROJECT_BINARY_DIR}/vapi/hicn.api.vapi.hpp
)

set(HICN_VPP_STARTUP_CONF_FILE
    ${CMAKE_BINARY_DIR}/startup.conf)

if (NOT VPP_HOME)
    set(VPP_HOME /usr)
endif()

if (NOT CMAKE_BUILD_TYPE)
    set (CMAKE_BUILD_TYPE "Release")
endif (NOT CMAKE_BUILD_TYPE)

SET(HICN_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR} CACHE STRING "hicn_install_prefix")

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/hicn)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/vapi)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/vnet/ip)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/vnet/fib)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/vnet/udp)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/vpp_plugins)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/vpp_plugins/hicn)

include(Packager)
extract_version()

# These files are missing from vpp binary distribution
execute_process(
  COMMAND ${CMAKE_COMMAND} -E make_directory ${PROJECT_BINARY_DIR}/vnet/fib/
  COMMAND ${CMAKE_COMMAND} -E make_directory ${PROJECT_BINARY_DIR}/vnet/udp/
  COMMAND
  bash -c
  "if [ ! -e ${CMAKE_CURRENT_BINARY_DIR}/vnet/fib/fib_entry_track.h ]; then
    curl https://raw.githubusercontent.com/FDio/vpp/v22.02-rc2/src/vnet/fib/fib_entry_track.h -o ${PROJECT_BINARY_DIR}/vnet/fib/fib_entry_track.h;
  fi;
  if [ ! -e ${CMAKE_CURRENT_BINARY_DIR}/vnet/udp/udp_encap.h ]; then
    curl https://raw.githubusercontent.com/FDio/vpp/v22.02-rc2/src/vnet/udp/udp_encap.h -o ${PROJECT_BINARY_DIR}/vnet/udp/udp_encap.h;
  fi;"
)

message("${VPP_HOME}/bin/vppapigen --includedir ${VPP_HOME}/include --input ${CMAKE_CURRENT_SOURCE_DIR}/hicn.api --output ${PROJECT_BINARY_DIR}/vpp_plugins/hicn/hicn.api.h --outputdir ${PROJECT_BINARY_DIR}/vpp_plugins/hicn/")
message("${VPP_HOME}/bin/vppapigen JSON --includedir ${VPP_HOME}/include --input ${CMAKE_CURRENT_SOURCE_DIR}/hicn.api --output ${PROJECT_BINARY_DIR}/vapi/hicn.api.json --outputdir ${PROJECT_BINARY_DIR}/vapi/")

execute_process(
  COMMAND ${CMAKE_COMMAND} -E make_directory ${PROJECT_BINARY_DIR}/vpp_plugins/hicn/
  COMMAND ${CMAKE_COMMAND} -E make_directory ${PROJECT_BINARY_DIR}/vapi/
  COMMAND ${VPP_HOME}/bin/vppapigen --includedir ${VPP_HOME}/include --input ${CMAKE_CURRENT_SOURCE_DIR}/hicn.api --output ${PROJECT_BINARY_DIR}/vpp_plugins/hicn/hicn.api.h --outputdir ${PROJECT_BINARY_DIR}/vpp_plugins/hicn/
  COMMAND ${VPP_HOME}/bin/vppapigen JSON --includedir ${VPP_HOME}/include --input ${CMAKE_CURRENT_SOURCE_DIR}/hicn.api --output ${PROJECT_BINARY_DIR}/vapi/hicn.api.json --outputdir ${PROJECT_BINARY_DIR}/vapi/
)
execute_process(
  COMMAND ${VPP_HOME}/bin/vapi_c_gen.py ${PROJECT_BINARY_DIR}/vapi/hicn.api.json
  COMMAND ${VPP_HOME}/bin/vapi_cpp_gen.py ${PROJECT_BINARY_DIR}/vapi/hicn.api.json
)

include_directories(SYSTEM)
include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${PROJECT_BINARY_DIR})

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHICN_VPP_PLUGIN=1")
add_library(hicn_plugin SHARED
    ${LIBHICN_FILES}
    ${HICN_PLUGIN_SOURCE_FILES}
    ${HICN_API_GENERATED_FILES}
    ${HICN_VAPI_GENERATED_FILES})

file(COPY ${HICN_API_HEADER_FILES} DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/vpp_plugins/hicn)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/vpp_plugins)

file(COPY ${LIBHICN_HEADER_FILES_SRC} DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/hicn)
file(COPY ${LIBHICN_HEADER_FILES_PROTOCOL} DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/hicn/protocol)
file(COPY ${LIBHICN_HEADER_FILES_UTIL} DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/hicn/util)

add_library(hicn_api_test_plugin SHARED
	${HICN_API_TEST_SOURCE_FILES}
        ${HICN_API_GENERATED_FILES})

set(VPP_INSTALL_PLUGIN ${HICN_INSTALL_PREFIX}/vpp_plugins)
set(VPP_INSTALL_API_TEST_PLUGIN ${HICN_INSTALL_PREFIX}/vpp_api_test_plugins CACHE STRING "vpp_install_api_test_plugin")
set(VPP_STARTUP_CONF /etc/vpp/)

set_target_properties(hicn_plugin
        PROPERTIES
        LINKER_LANGUAGE C
        INSTALL_RPATH ${VPP_INSTALL_PLUGIN}
        COMPILE_FLAGS "-march=native -Wno-address-of-packed-member"
        PREFIX "")
set_target_properties(hicn_api_test_plugin
        PROPERTIES
        LINKER_LANGUAGE C
        COMPILE_FLAGS "-march=native -Wno-address-of-packed-member"
        PREFIX "")

if (${CMAKE_BUILD_TYPE} MATCHES "Debug")
    target_compile_definitions(hicn_plugin PRIVATE "CLIB_DEBUG")
    target_compile_definitions(hicn_api_test_plugin PRIVATE "CLIB_DEBUG")
endif()

message (STATUS "hicn-plugin variable ${HICN_PLUGIN}")

install(DIRECTORY
        DESTINATION ${VPP_INSTALL_PLUGIN}
        COMPONENT ${HICN_PLUGIN})
install(TARGETS hicn_plugin
        DESTINATION
        ${VPP_INSTALL_PLUGIN}
        COMPONENT ${HICN_PLUGIN})

install(DIRECTORY
        DESTINATION ${VPP_INSTALL_API_TEST_PLUGIN}
        COMPONENT ${HICN_PLUGIN})
install(TARGETS hicn_api_test_plugin
        DESTINATION ${VPP_INSTALL_API_TEST_PLUGIN}
        COMPONENT ${HICN_PLUGIN})

install(FILES ${HICN_API_HEADER_FILES} ${HICN_API_GENERATED_FILES}
        DESTINATION ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_INCLUDEDIR}/vpp_plugins/hicn
        COMPONENT ${HICN_PLUGIN}-dev)

install(FILES ${HICN_API_GENERATED_FILES}
        DESTINATION ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_INCLUDEDIR}/vpp_plugins/hicn
        COMPONENT ${HICN_PLUGIN}-dev)

install(FILES ${HICN_VAPI_GENERATED_FILES}
        DESTINATION ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_INCLUDEDIR}/vapi
        COMPONENT ${HICN_PLUGIN}-dev)

#Set variables for other project depending on hicn-plugin
set(HICNPLUGIN_INCLUDE_DIRS
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}/vpp_plugins
    ${VPP_INCLUDE_DIRS}
    CACHE INTERNAL "" FORCE)
set(HICNPLUGIN_LIBRARIES ${VPP_LIBRARIES} CACHE INTERNAL "" FORCE)
