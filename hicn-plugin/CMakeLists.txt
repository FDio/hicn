# Copyright (c) 2017-2019 Cisco and/or its affiliates.
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
project(hicn-plugin)

include(GNUInstallDirs)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH}
    "${CMAKE_CURRENT_SOURCE_DIR}/../cmake/Modules/"
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules/"
)

set (CMAKE_CXX_STANDARD 11)
set (CMAKE_C_STANDARD 11)

# Check for memfd_create syscall
include(CheckSymbolExists)
CHECK_SYMBOL_EXISTS ( "__NR_memfd_create" "sys/syscall.h" HAVE_MEMFD_CREATE )
if ( HAVE_MEMFD_CREATE )
    add_definitions ( -DHAVE_MEMFD_CREATE )
endif()

set(HICN_PLUGIN hicn-plugin CACHE INTERNAL "" FORCE)

include (Packaging)

# Dependencies
find_package(Vpp REQUIRED)

include_directories(${VPP_INCLUDE_DIR})

set(LIBHICN_FILES
    ../lib/src/mapme.c
    ../lib/src/name.c
    ../lib/src/ops.c
    ../lib/src/protocol/ah.c
    ../lib/src/protocol/icmp.c
    ../lib/src/protocol/ipv4.c
    ../lib/src/protocol/ipv6.c
    ../lib/src/protocol/tcp.c
)

set(LIBHICN_HEADER_FILES_SRC
    ../lib/includes/hicn/hicn.h
    ../lib/includes/hicn/base.h
    ../lib/includes/hicn/common.h
    ../lib/includes/hicn/error.h
    ../lib/includes/hicn/header.h
    ../lib/includes/hicn/name.h
    ../lib/includes/hicn/protocol.h
    ../lib/includes/hicn/ops.h
    ../lib/includes/hicn/mapme.h
)

set(LIBHICN_HEADER_FILES_PROTOCOL
    ../lib/includes/hicn/protocol/ah.h
    ../lib/includes/hicn/protocol/icmp.h
    ../lib/includes/hicn/protocol/icmprd.h
    ../lib/includes/hicn/protocol/ipv4.h
    ../lib/includes/hicn/protocol/ipv6.h
    ../lib/includes/hicn/protocol/tcp.h
    ../lib/includes/hicn/protocol/udp.h
)

set(LIBHICN_HEADER_FILES_UTIL
    ../lib/includes/hicn/util/ip_address.h
    ../lib/includes/hicn/util/token.h
    ../lib/includes/hicn/util/types.h
)

set(HICN_PLUGIN_SOURCE_FILES
    src/hicn.c
    src/hicn_api.c
    src/cli.c
    src/hashtb.c
    src/mgmt.c
    src/pcs.c
    src/route.c
    src/strategy_dpo_manager.c
    src/strategy.c
    src/interest_pcslookup_node.c
    src/interest_hitpit_node.c
    src/interest_hitcs_node.c
    src/data_pcslookup_node.c
    src/data_fwd_node.c
    src/data_push_node.c
    src/error.c
    src/faces/face_cli.c
    src/faces/face.c
    src/faces/ip/face_ip.c
    src/faces/ip/face_ip_cli.c
    src/faces/ip/face_ip_node.c
    src/faces/ip/iface_ip_node.c
    src/faces/ip/dpo_ip.c
    src/faces/udp/face_udp.c
    src/faces/udp/face_udp_cli.c
    src/faces/udp/face_udp_node.c
    src/faces/udp/iface_udp_node.c
    src/faces/udp/dpo_udp.c
    src/faces/app/address_mgr.c
    src/faces/app/face_cons.c
    src/faces/app/face_prod.c
    src/faces/app/face_prod_node.c
    src/faces/app/face_app_cli.c
    src/punt.c
    src/pg.c
    src/strategies/dpo_mw.c
    src/strategies/strategy_mw.c
    src/strategies/strategy_mw_cli.c
    src/strategies/dpo_rr.c
    src/strategies/strategy_rr.c
    src/cache_policies/cs_lru.c
    src/mapme_ack_node.c
    src/mapme_ctrl_node.c
    src/mapme_eventmgr.c
)

set(HICN_PLUGIN_HEADER_FILES
    src/hicn_all_api_h.h
    src/hashtb.h
    src/mgmt.h
    src/params.h
    src/pcs.h
    src/hicn_api.h
    src/hicn.h
    src/state.h
    src/infra.h
    src/hicn_msg_enum.h
    src/parser.h
    src/route.h
    src/strategy_dpo_ctx.h
    src/strategy_dpo_manager.h
    src/strategy.h
    src/interest_pcslookup.h
    src/interest_hitpit.h
    src/interest_hitcs.h
    src/data_pcslookup.h
    src/data_fwd.h
    src/error.h
    src/face_db.h
    src/faces/face.h
    src/faces/ip/face_ip.h
    src/faces/ip/face_ip_node.h
    src/faces/ip/iface_ip_node.h
    src/faces/ip/dpo_ip.h
    src/faces/udp/face_udp.h
    src/faces/udp/face_udp_node.h
    src/faces/udp/iface_udp_node.h
    src/faces/udp/dpo_udp.h
    src/faces/app/address_mgr.h
    src/faces/app/face_cons.h
    src/faces/app/face_prod.h
    src/punt.h
    src/pg.h
    src/strategies/dpo_mw.h
    src/strategies/strategy_mw.h
    src/strategies/dpo_rr.h
    src/strategies/strategy_rr.h
    src/cache_policies/cs_policy.h
    src/cache_policies/cs_lru.h
    src/mapme.h
    src/mapme_ack.h
    src/mapme_ctrl.h
    src/mapme_eventmgr.h
)

set(HICN_API_TEST_SOURCE_FILES
    src/hicn_api_test.c
    src/error.c)

set(HICN_API_HEADER_FILES
    src/hicn_msg_enum.h
    src/hicn_all_api_h.h
    src/hicn_api.h
    src/error.h)

set(HICN_API_GENERATED_FILES
    ${CMAKE_CURRENT_BINARY_DIR}/vpp_plugins/hicn/hicn.api.h)

set(HICN_VAPI_GENERATED_FILES
    ${CMAKE_CURRENT_BINARY_DIR}/vapi/hicn.api.vapi.h
    ${CMAKE_CURRENT_BINARY_DIR}/vapi/hicn.api.vapi.hpp)

set(HICN_VPP_STARTUP_CONF_FILE
    ${CMAKE_BINARY_DIR}/startup.conf)

if (NOT VPP_HOME)
    set(VPP_HOME /usr)
endif()

if (NOT CMAKE_BUILD_TYPE)
    set (CMAKE_BUILD_TYPE "Release")
endif (NOT CMAKE_BUILD_TYPE)

SET(HICN_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR} CACHE STRING "hicn_install_prefix")

if (CMAKE_BUILD_TYPE STREQUAL "Release")
   set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -Wall  -march=native -O3 -g")
elseif (CMAKE_BUILD_TYPE STREQUAL "Debug")
   set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wall -march=native -O0 -g")
   add_definitions(-DCLIB_DEBUG -fPIC -fstack-protector-all)
endif()

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/hicn)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/vapi)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/vnet/ip)

# These files are missing from vpp binary distribution
execute_process(
    COMMAND
    bash -c
    "if [ ! -e ${CMAKE_CURRENT_BINARY_DIR}/vapi_json_parser.py ]; then
        curl https://raw.githubusercontent.com/FDio/vpp/master/src/vpp-api/vapi/vapi_json_parser.py -o ${CMAKE_CURRENT_BINARY_DIR}/vapi_json_parser.py;
    fi;
    if [ ! -e ${CMAKE_CURRENT_BINARY_DIR}/vapi_c_gen.py ]; then
        curl https://raw.githubusercontent.com/FDio/vpp/master/src/vpp-api/vapi/vapi_c_gen.py -o ${CMAKE_CURRENT_BINARY_DIR}/vapi_c_gen.py;
    fi;
    if [ ! -e ${CMAKE_CURRENT_BINARY_DIR}/vapi_cpp_gen.py ]; then
        curl https://raw.githubusercontent.com/FDio/vpp/master/src/vpp-api/vapi/vapi_cpp_gen.py -o ${CMAKE_CURRENT_BINARY_DIR}/vapi_cpp_gen.py;
    fi;
    if [ ! -e ${CMAKE_CURRENT_BINARY_DIR}/vnet/ip/ip_types.api ]; then
        curl https://raw.githubusercontent.com/FDio/vpp/master/src/vnet/ip/ip_types.api -o ${CMAKE_CURRENT_BINARY_DIR}/vnet/ip/ip_types.api;
    fi;
    if [ ! -e ${CMAKE_CURRENT_BINARY_DIR}/vnet/ip/ip_format_fns.h ]; then
        curl https://raw.githubusercontent.com/FDio/vpp/master/src/vnet/ip/ip_format_fns.h -o ${CMAKE_CURRENT_BINARY_DIR}/vnet/ip/ip_format_fns.h;
    fi;
    chmod +x ${CMAKE_CURRENT_BINARY_DIR}/vapi_json_parser.py ${CMAKE_CURRENT_BINARY_DIR}/vapi_c_gen.py ${CMAKE_CURRENT_BINARY_DIR}/vapi_cpp_gen.py"
)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/vpp_plugins/hicn/hicn.api.h ${CMAKE_CURRENT_BINARY_DIR}/vapi/hicn.api.json
    COMMAND ${VPP_HOME}/bin/vppapigen ARGS --includedir ${CMAKE_CURRENT_BINARY_DIR} --input ${CMAKE_CURRENT_SOURCE_DIR}/src/hicn.api --output ${CMAKE_CURRENT_BINARY_DIR}/vpp_plugins/hicn/hicn.api.h --outputdir ${CMAKE_CURRENT_BINARY_DIR}/vpp_plugins/hicn/
    COMMAND ${VPP_HOME}/bin/vppapigen ARGS JSON --includedir ${CMAKE_CURRENT_BINARY_DIR} --input ${CMAKE_CURRENT_SOURCE_DIR}/src/hicn.api --output ${CMAKE_CURRENT_BINARY_DIR}/vapi/hicn.api.json --outputdir ${CMAKE_CURRENT_BINARY_DIR}/vpp_plugins/hicn/
)
add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/vapi/hicn.api.vapi.h ${CMAKE_CURRENT_BINARY_DIR}/vapi/hicn.api.vapi.hpp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/vapi_c_gen.py ARGS ${CMAKE_CURRENT_BINARY_DIR}/vapi/hicn.api.json
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/vapi_cpp_gen.py ARGS ${CMAKE_CURRENT_BINARY_DIR}/vapi/hicn.api.json
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/vapi/hicn.api.json
)

include_directories(SYSTEM)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

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
        PREFIX "")
set_target_properties(hicn_api_test_plugin
        PROPERTIES
        LINKER_LANGUAGE C
        PREFIX "")

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
        COMPONENT ${HICN_PLUGIN_DEV})

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
