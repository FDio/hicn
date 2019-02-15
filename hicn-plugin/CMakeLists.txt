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

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
	set(HICN_PLUGIN hicn-plugin)
endif()

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
    ../lib/src/hicn.h
    ../lib/src/base.h
    ../lib/src/common.h
    ../lib/src/error.h
    ../lib/src/header.h
    ../lib/src/name.h
    ../lib/src/protocol.h
    ../lib/src/ops.h
    ../lib/src/mapme.h
)

set(LIBHICN_HEADER_FILES_PROTOCOL
    ../lib/src/protocol/ah.h
    ../lib/src/protocol/icmp.h
    ../lib/src/protocol/icmprd.h
    ../lib/src/protocol/ipv4.h
    ../lib/src/protocol/ipv6.h
    ../lib/src/protocol/tcp.h
    ../lib/src/protocol/udp.h
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

set(HICN_API_TEST_HEADER_FILES
    src/hicn_msg_enum.h
    src/hicn_all_api_h.h
    src/hicn_api.h
    src/error.h)

set(HICN_API_GENERATED_FILES
    ${CMAKE_CURRENT_BINARY_DIR}/vpp_plugins/hicn/hicn.api.h)

set(HICN_VAPI_GENERATED_FILES
    ${CMAKE_CURRENT_BINARY_DIR}/vpp_plugins/hicn/hicn.api.vapi.h
    ${CMAKE_CURRENT_BINARY_DIR}/vpp_plugins/hicn/hicn.api.vapi.hpp)

if (NOT VPP_HOME)
    set(VPP_HOME /usr)
endif()

if (NOT CMAKE_BUILD_TYPE)
    set (CMAKE_BUILD_TYPE "Release")
endif (NOT CMAKE_BUILD_TYPE)

SET(HICN_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX}/lib CACHE STRING "hicn_install_prefix")

if (CMAKE_BUILD_TYPE STREQUAL "Release")
   set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -Wall  -march=native -O3 -g")
elseif (CMAKE_BUILD_TYPE STREQUAL "Debug")
   set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wall -march=native -O0 -g")
   add_definitions(-DCLIB_DEBUG -fPIC -fstack-protector-all)
endif()

execute_process(COMMAND mkdir -p ${CMAKE_CURRENT_BINARY_DIR}/hicn)
# These files are missing from vpp binary distribution
execute_process(
    COMMAND curl https://raw.githubusercontent.com/FDio/vpp/master/src/vpp-api/vapi/vapi_json_parser.py -o vapi_json_parser.py
    COMMAND curl https://raw.githubusercontent.com/FDio/vpp/master/src/vpp-api/vapi/vapi_c_gen.py  -o vapi_c_gen.py
    COMMAND curl https://raw.githubusercontent.com/FDio/vpp/master/src/vpp-api/vapi/vapi_cpp_gen.py  -o vapi_cpp_gen.py
    )

add_custom_command(
        COMMAND chmod +x  vapi_json_parser.py vapi_c_gen.py vapi_cpp_gen.py
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/vpp_plugins/hicn/hicn.api.h
        COMMAND ${VPP_HOME}/bin/vppapigen --input ${CMAKE_CURRENT_SOURCE_DIR}/src/hicn.api --output ${CMAKE_CURRENT_BINARY_DIR}/vpp_plugins/hicn/hicn.api.h
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/hicn.api
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/vpp_plugins/hicn/hicn.api.json
        COMMAND ${VPP_HOME}/bin/vppapigen JSON --input ${CMAKE_CURRENT_SOURCE_DIR}/src/hicn.api --output ${CMAKE_CURRENT_BINARY_DIR}/vpp_plugins/hicn/hicn.api.json
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/vpp_plugins/hicn/hicn.api.vapi.h
        COMMAND ${CMAKE_CURRENT_BINARY_DIR}/vapi_c_gen.py ${CMAKE_CURRENT_BINARY_DIR}/vpp_plugins/hicn/hicn.api.json
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/vpp_plugins/hicn/hicn.api.vapi.hpp
        COMMAND ${CMAKE_CURRENT_BINARY_DIR}/vapi_cpp_gen.py ${CMAKE_CURRENT_BINARY_DIR}/vpp_plugins/hicn/hicn.api.json
        )

include_directories(SYSTEM)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHICN_VPP_PLUGIN=1")
add_library(hicn_plugin SHARED
    ${LIBHICN_FILES}
    ${HICN_PLUGIN_SOURCE_FILES}
    ${HICN_API_GENERATED_FILES}
    ${HICN_VAPI_GENERATED_FILES})

file(COPY ${HICN_API_TEST_HEADER_FILES} DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/vpp_plugins/hicn)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/vpp_plugins)

file(COPY ${LIBHICN_HEADER_FILES_SRC} DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/hicn)
file(COPY ${LIBHICN_HEADER_FILES_PROTOCOL} DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/hicn/protocol)

add_library(hicn_api_test_plugin SHARED
	${HICN_API_TEST_SOURCE_FILES}
        ${HICN_API_GENERATED_FILES})

set(VPP_INSTALL_PLUGIN ${HICN_INSTALL_PREFIX}/vpp_plugins)
set(VPP_INSTALL_API_TEST_PLUGIN ${HICN_INSTALL_PREFIX}/vpp_api_test_plugins CACHE STRING "vpp_install_api_test_plugin")

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

install(FILES ${HICN_API_TEST_HEADER_FILES} ${HICN_API_GENERATED_FILES}
        DESTINATION ${CMAKE_INSTALL_PREFIX}/include/vpp_plugins/hicn
        COMPONENT ${HICN_PLUGIN})

install(FILES ${HICN_VAPI_GENERATED_FILES}
        DESTINATION ${CMAKE_INSTALL_PREFIX}/include/vapi
        COMPONENT ${HICN_PLUGIN})