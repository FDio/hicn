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

cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

# Dependencies

find_package(Vpp REQUIRED)

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
  find_package(Libtransport REQUIRED)
  find_package(Libhicn REQUIRED)
else()
  if (DISABLE_SHARED_LIBRARIES)
    set(LIBTRANSPORT_LIBRARIES ${LIBTRANSPORT_STATIC})
    set(LIBHICN_LIBRARIES ${LIBHICN_STATIC})
  else ()
    set(LIBTRANSPORT_LIBRARIES ${LIBTRANSPORT_SHARED})
    set(LIBHICN_LIBRARIES ${LIBHICN_SHARED})
  endif ()

  list(APPEND DEPENDENCIES
    ${LIBHICN_LIBRARIES}
    ${LIBTRANSPORT_LIBRARIES}
  )
endif()

set(HICN_PLUGIN_SOURCE_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/hicn_plugin.c
)

set(HICN_PLUGIN_HEADER_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/hicn_buffer.h
)

set(HICN_NETWORK_PLUGIN_SOURCE_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/network/hicn_config.c
    ${CMAKE_CURRENT_SOURCE_DIR}/network/hicn_api.c
    ${CMAKE_CURRENT_SOURCE_DIR}/network/cli.c
    ${CMAKE_CURRENT_SOURCE_DIR}/network/hashtb.c
    ${CMAKE_CURRENT_SOURCE_DIR}/network/mgmt.c
    ${CMAKE_CURRENT_SOURCE_DIR}/network/pcs.c
    ${CMAKE_CURRENT_SOURCE_DIR}/network/route.c
    ${CMAKE_CURRENT_SOURCE_DIR}/network/strategy_dpo_ctx.c
    ${CMAKE_CURRENT_SOURCE_DIR}/network/strategy_dpo_manager.c
    ${CMAKE_CURRENT_SOURCE_DIR}/network/strategy_node.c
    ${CMAKE_CURRENT_SOURCE_DIR}/network/interest_pcslookup_node.c
    ${CMAKE_CURRENT_SOURCE_DIR}/network/interest_hitpit_node.c
    ${CMAKE_CURRENT_SOURCE_DIR}/network/interest_hitcs_node.c
    ${CMAKE_CURRENT_SOURCE_DIR}/network/data_input_node.c
    ${CMAKE_CURRENT_SOURCE_DIR}/network/data_pcslookup_node.c
    ${CMAKE_CURRENT_SOURCE_DIR}/network/data_fwd_node.c
    ${CMAKE_CURRENT_SOURCE_DIR}/network/error.c
    ${CMAKE_CURRENT_SOURCE_DIR}/network/faces/face_cli.c
    ${CMAKE_CURRENT_SOURCE_DIR}/network/faces/face.c
    ${CMAKE_CURRENT_SOURCE_DIR}/network/faces/face_node.c
    ${CMAKE_CURRENT_SOURCE_DIR}/network/faces/iface_node.c
    ${CMAKE_CURRENT_SOURCE_DIR}/network/faces/app/address_mgr.c
    ${CMAKE_CURRENT_SOURCE_DIR}/network/faces/app/face_cons.c
    ${CMAKE_CURRENT_SOURCE_DIR}/network/faces/app/face_prod.c
    ${CMAKE_CURRENT_SOURCE_DIR}/network/faces/app/face_prod_node.c
    ${CMAKE_CURRENT_SOURCE_DIR}/network/faces/app/face_app_cli.c
    ${CMAKE_CURRENT_SOURCE_DIR}/network/pg.c
    ${CMAKE_CURRENT_SOURCE_DIR}/network/strategies/dpo_mw.c
    ${CMAKE_CURRENT_SOURCE_DIR}/network/strategies/strategy_mw.c
    ${CMAKE_CURRENT_SOURCE_DIR}/network/strategies/strategy_mw_cli.c
    ${CMAKE_CURRENT_SOURCE_DIR}/network/strategies/dpo_rr.c
    ${CMAKE_CURRENT_SOURCE_DIR}/network/strategies/strategy_rr.c
    ${CMAKE_CURRENT_SOURCE_DIR}/network/cache_policies/cs_lru.c
    ${CMAKE_CURRENT_SOURCE_DIR}/network/mapme_ack_node.c
    ${CMAKE_CURRENT_SOURCE_DIR}/network/mapme_ctrl_node.c
    ${CMAKE_CURRENT_SOURCE_DIR}/network/mapme_eventmgr.c
    ${CMAKE_CURRENT_SOURCE_DIR}/network/udp_tunnels/udp_decap_node.c
    ${CMAKE_CURRENT_SOURCE_DIR}/network/udp_tunnels/udp_tunnel.c
)

set(HICN_NETWORK_PLUGIN_HEADER_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/network/hashtb.h
    ${CMAKE_CURRENT_SOURCE_DIR}/network/mgmt.h
    ${CMAKE_CURRENT_SOURCE_DIR}/network/params.h
    ${CMAKE_CURRENT_SOURCE_DIR}/network/pcs.h
    ${CMAKE_CURRENT_SOURCE_DIR}/network/hicn.h
    ${CMAKE_CURRENT_SOURCE_DIR}/network/state.h
    ${CMAKE_CURRENT_SOURCE_DIR}/network/infra.h
    ${CMAKE_CURRENT_SOURCE_DIR}/network/parser.h
    ${CMAKE_CURRENT_SOURCE_DIR}/network/route.h
    ${CMAKE_CURRENT_SOURCE_DIR}/network/strategy_dpo_ctx.h
    ${CMAKE_CURRENT_SOURCE_DIR}/network/strategy_dpo_manager.h
    ${CMAKE_CURRENT_SOURCE_DIR}/network/strategy.h
    ${CMAKE_CURRENT_SOURCE_DIR}/network/interest_pcslookup.h
    ${CMAKE_CURRENT_SOURCE_DIR}/network/interest_hitpit.h
    ${CMAKE_CURRENT_SOURCE_DIR}/network/interest_hitcs.h
    ${CMAKE_CURRENT_SOURCE_DIR}/network/data_pcslookup.h
    ${CMAKE_CURRENT_SOURCE_DIR}/network/data_fwd.h
    ${CMAKE_CURRENT_SOURCE_DIR}/network/face_db.h
    ${CMAKE_CURRENT_SOURCE_DIR}/network/faces/face.h
    ${CMAKE_CURRENT_SOURCE_DIR}/network/faces/face_node.h
    ${CMAKE_CURRENT_SOURCE_DIR}/network/faces/iface_node.h
    ${CMAKE_CURRENT_SOURCE_DIR}/network/faces/face_dpo.h
    ${CMAKE_CURRENT_SOURCE_DIR}/network/faces/app/address_mgr.h
    ${CMAKE_CURRENT_SOURCE_DIR}/network/faces/app/face_cons.h
    ${CMAKE_CURRENT_SOURCE_DIR}/network/faces/app/face_prod.h
    ${CMAKE_CURRENT_SOURCE_DIR}/network/pg.h
    ${CMAKE_CURRENT_SOURCE_DIR}/network/strategies/dpo_mw.h
    ${CMAKE_CURRENT_SOURCE_DIR}/network/strategies/strategy_mw.h
    ${CMAKE_CURRENT_SOURCE_DIR}/network/strategies/dpo_rr.h
    ${CMAKE_CURRENT_SOURCE_DIR}/network/strategies/strategy_rr.h
    ${CMAKE_CURRENT_SOURCE_DIR}/network/cache_policies/cs_policy.h
    ${CMAKE_CURRENT_SOURCE_DIR}/network/cache_policies/cs_lru.h
    ${CMAKE_CURRENT_SOURCE_DIR}/network/mapme.h
    ${CMAKE_CURRENT_SOURCE_DIR}/network/mapme_ack.h
    ${CMAKE_CURRENT_SOURCE_DIR}/network/mapme_ctrl.h
    ${CMAKE_CURRENT_SOURCE_DIR}/network/mapme_eventmgr.h
    ${CMAKE_CURRENT_SOURCE_DIR}/network/udp_tunnels/udp_tunnel.h
)

set(HICN_HS_PLUGIN_SOURCE_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/host_stack/host_stack.c
    ${CMAKE_CURRENT_SOURCE_DIR}/host_stack/error.c
    ${CMAKE_CURRENT_SOURCE_DIR}/host_stack/cbr_proto.c
    ${CMAKE_CURRENT_SOURCE_DIR}/host_stack/cli.c
    ${CMAKE_CURRENT_SOURCE_DIR}/host_stack/input_node.c
    ${CMAKE_CURRENT_SOURCE_DIR}/host_stack/output_node.c
    ${CMAKE_CURRENT_SOURCE_DIR}/host_stack/producer_dpo.c
    ${CMAKE_CURRENT_SOURCE_DIR}/host_stack/route.c
    ${CMAKE_CURRENT_SOURCE_DIR}/host_stack/test/hicn_hs_client.c
    ${CMAKE_CURRENT_SOURCE_DIR}/host_stack/test/hicn_hs_server.c
)

set(HICN_HS_PLUGIN_HEADER_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/host_stack/error.h
    ${CMAKE_CURRENT_SOURCE_DIR}/host_stack/debug.h
    ${CMAKE_CURRENT_SOURCE_DIR}/host_stack/host_stack.h
    ${CMAKE_CURRENT_SOURCE_DIR}/host_stack/inlines.h
    ${CMAKE_CURRENT_SOURCE_DIR}/host_stack/producer_dpo.h
    ${CMAKE_CURRENT_SOURCE_DIR}/host_stack/proto.h
    ${CMAKE_CURRENT_SOURCE_DIR}/host_stack/route.h
    ${CMAKE_CURRENT_SOURCE_DIR}/host_stack/utils.h
)

set(HICN_API_TEST_SOURCE_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/network/hicn_api_test.c
    ${CMAKE_CURRENT_SOURCE_DIR}/network/error.c
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
    ${PROJECT_BINARY_DIR}/vapi/hicn.api.vapi.hpp)

if (NOT VPP_HOME)
    set(VPP_HOME /usr)
endif()

if (NOT CMAKE_BUILD_TYPE)
    set (CMAKE_BUILD_TYPE "Release")
endif (NOT CMAKE_BUILD_TYPE)

SET(HICN_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR} CACHE STRING "hicn_install_prefix")

set(COMPILE_FLAGS "-march=native")
set(COMPILE_DEFINITIONS "-DHICN_VPP_PLUGIN=1")

file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/hicn)
file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/vapi)
file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/vnet/ip)
file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/vnet/fib)
file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/vnet/udp)
file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/vpp_plugins/hicn)

# These files are missing from vpp binary distribution
execute_process(
    COMMAND
    bash -c
    "if [ ! -e ${PROJECT_BINARY_DIR}/vapi_json_parser.py ]; then
        curl https://raw.githubusercontent.com/FDio/vpp/stable/2005/src/vpp-api/vapi/vapi_json_parser.py -o ${PROJECT_BINARY_DIR}/vapi_json_parser.py;
    fi;
    if [ ! -e ${PROJECT_BINARY_DIR}/vapi_c_gen.py ]; then
        curl https://raw.githubusercontent.com/FDio/vpp/stable/2005/src/vpp-api/vapi/vapi_c_gen.py -o ${PROJECT_BINARY_DIR}/vapi_c_gen.py;
    fi;
    if [ ! -e ${PROJECT_BINARY_DIR}/vapi_cpp_gen.py ]; then
        curl https://raw.githubusercontent.com/FDio/vpp/stable/2005/src/vpp-api/vapi/vapi_cpp_gen.py -o ${PROJECT_BINARY_DIR}/vapi_cpp_gen.py;
    fi;
    if [ ! -e ${PROJECT_BINARY_DIR}/vnet/ip/ip_types.api ]; then
        curl https://raw.githubusercontent.com/FDio/vpp/stable/2005/src/vnet/ip/ip_types.api -o ${PROJECT_BINARY_DIR}/vnet/ip/ip_types.api;
    fi;
    if [ ! -e ${PROJECT_BINARY_DIR}/vnet/ip/ip_format_fns.h ]; then
        curl https://raw.githubusercontent.com/FDio/vpp/stable/2005/src/vnet/ip/ip_format_fns.h -o ${PROJECT_BINARY_DIR}/vnet/ip/ip_format_fns.h;
    fi;
    if [ ! -e ${PROJECT_BINARY_DIR}/vnet/fib/fib_entry_track.h ]; then
        curl https://raw.githubusercontent.com/FDio/vpp/stable/2005/src/vnet/fib/fib_entry_track.h -o ${PROJECT_BINARY_DIR}/vnet/fib/fib_entry_track.h;
    fi;
    if [ ! -e ${PROJECT_BINARY_DIR}/vnet/udp/udp_encap.h ]; then
        curl https://raw.githubusercontent.com/FDio/vpp/stable/2005/src/vnet/udp/udp_encap.h -o ${PROJECT_BINARY_DIR}/vnet/udp/udp_encap.h;
    fi;

    chmod +x ${PROJECT_BINARY_DIR}/vapi_json_parser.py ${PROJECT_BINARY_DIR}/vapi_c_gen.py ${PROJECT_BINARY_DIR}/vapi_cpp_gen.py"
)

execute_process(
    COMMAND ${VPP_HOME}/bin/vppapigen --includedir ${PROJECT_BINARY_DIR} --input ${CMAKE_CURRENT_SOURCE_DIR}/network/hicn.api --output ${PROJECT_BINARY_DIR}/vpp_plugins/hicn/hicn.api.h --outputdir ${PROJECT_BINARY_DIR}/vpp_plugins/hicn/
    COMMAND ${VPP_HOME}/bin/vppapigen JSON --includedir ${PROJECT_BINARY_DIR} --input ${CMAKE_CURRENT_SOURCE_DIR}/network/hicn.api --output ${PROJECT_BINARY_DIR}/vapi/hicn.api.json --outputdir ${PROJECT_BINARY_DIR}/vapi/
)
execute_process(
    COMMAND ${PROJECT_BINARY_DIR}/vapi_c_gen.py ${PROJECT_BINARY_DIR}/vapi/hicn.api.json
    COMMAND ${PROJECT_BINARY_DIR}/vapi_cpp_gen.py ${PROJECT_BINARY_DIR}/vapi/hicn.api.json
)

set(HICN_PLUGIN_INCLUDE_DIRS_INTERNAL
    ${HICNPLUGIN_INCLUDE_DIRS}
    ${PROJECT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${LIBTRANSPORT_INCLUDE_DIRS}
    ${LIBHICN_INCLUDE_DIRS}
    ${VPP_INCLUDE_DIR}
)

build_library(hicn_plugin
    SHARED
    SOURCES ${HICN_PLUGIN_SOURCE_FILES} ${HICN_NETWORK_PLUGIN_SOURCE_FILES} ${HICN_HS_PLUGIN_SOURCE_FILES}
    INSTALL_HEADERS ${HICN_API_HEADER_FILES} ${HICN_API_GENERATED_FILES}
    LINK_LIBRARIES ${LIBTRANSPORT_LIBRARIES} ${LIBHICN_LIBRARIES}
    DEPENDS ${DEPENDENCIES}
    COMPONENT ${HICN_PLUGIN}
    INCLUDE_DIRS ${HICN_PLUGIN_INCLUDE_DIRS_INTERNAL}
    HEADER_ROOT_DIR "vpp_plugins/hicn"
    LIBRARY_ROOT_DIR "vpp_plugins"
    DEFINITIONS ${COMPILE_DEFINITIONS}
    COMPILE_FLAGS ${COMPILE_FLAGS}
)

build_library(hicn_api_test_plugin
    SHARED
    SOURCES ${HICN_API_TEST_SOURCE_FILES}
    INSTALL_HEADERS ${HICN_VAPI_GENERATED_FILES}
    COMPONENT ${HICN_PLUGIN}
    INCLUDE_DIRS ${HICN_PLUGIN_INCLUDE_DIRS_INTERNAL}
    HEADER_ROOT_DIR "vapi"
    LIBRARY_ROOT_DIR "vpp_api_test_plugins"
    DEFINITIONS ${COMPILE_DEFINITIONS}
    COMPILE_FLAGS ${COMPILE_FLAGS}
)

set_target_properties(hicn_plugin.shared
    PROPERTIES
    LINKER_LANGUAGE C
    INSTALL_RPATH "${VPP_INSTALL_PLUGIN}:${HICN_INSTALL_PREFIX}:/home/ubuntu/host-stack/vpp/build-root/install-vpp_debug-native/vpp/lib"
    PREFIX ""
)

set_target_properties(hicn_api_test_plugin.shared
    PROPERTIES
    LINKER_LANGUAGE C
    INSTALL_RPATH "${VPP_INSTALL_PLUGIN}:${HICN_INSTALL_PREFIX}:/home/ubuntu/host-stack/vpp/build-root/install-vpp_debug-native/vpp/lib"
    PREFIX ""
)

message (STATUS "hicn-plugin variable ${HICN_PLUGIN}")
