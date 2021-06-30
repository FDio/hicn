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

list(APPEND HEADER_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/indexer.h
  ${CMAKE_CURRENT_SOURCE_DIR}/incremental_indexer_bytestream.h
  ${CMAKE_CURRENT_SOURCE_DIR}/manifest_incremental_indexer_bytestream.h
  ${CMAKE_CURRENT_SOURCE_DIR}/index_manager_bytestream.h
  ${CMAKE_CURRENT_SOURCE_DIR}/reassembly.h
  ${CMAKE_CURRENT_SOURCE_DIR}/datagram_reassembly.h
  ${CMAKE_CURRENT_SOURCE_DIR}/byte_stream_reassembly.h
  ${CMAKE_CURRENT_SOURCE_DIR}/congestion_window_protocol.h
  ${CMAKE_CURRENT_SOURCE_DIR}/rate_estimation.h
  ${CMAKE_CURRENT_SOURCE_DIR}/transport_protocol.h
  ${CMAKE_CURRENT_SOURCE_DIR}/production_protocol.h
  ${CMAKE_CURRENT_SOURCE_DIR}/prod_protocol_bytestream.h
  ${CMAKE_CURRENT_SOURCE_DIR}/prod_protocol_rtc.h
  ${CMAKE_CURRENT_SOURCE_DIR}/raaqm.h
  ${CMAKE_CURRENT_SOURCE_DIR}/raaqm_data_path.h
  ${CMAKE_CURRENT_SOURCE_DIR}/cbr.h
  ${CMAKE_CURRENT_SOURCE_DIR}/errors.h
  ${CMAKE_CURRENT_SOURCE_DIR}/data_processing_events.h
  ${CMAKE_CURRENT_SOURCE_DIR}/fec_base.h
)

list(APPEND SOURCE_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/indexer.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/incremental_indexer_bytestream.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/manifest_incremental_indexer_bytestream.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/index_manager_bytestream.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/reassembly.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/datagram_reassembly.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/byte_stream_reassembly.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/transport_protocol.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/production_protocol.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/prod_protocol_bytestream.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/prod_protocol_rtc.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/raaqm.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/rate_estimation.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/raaqm_data_path.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/cbr.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/errors.cc
)

set(RAAQM_CONFIG_INSTALL_PREFIX
  ${CMAKE_INSTALL_FULL_SYSCONFDIR}/hicn
)

set(raaqm_config_path
  ${RAAQM_CONFIG_INSTALL_PREFIX}/consumer.conf
  PARENT_SCOPE
)

set(TRANSPORT_CONFIG
  ${CMAKE_CURRENT_SOURCE_DIR}/consumer.conf
)

install(
  FILES ${TRANSPORT_CONFIG}
  DESTINATION ${CMAKE_INSTALL_FULL_SYSCONFDIR}/hicn
  COMPONENT ${LIBTRANSPORT_COMPONENT}
)

add_subdirectory(rtc)
add_subdirectory(fec)

set(SOURCE_FILES ${SOURCE_FILES} PARENT_SCOPE)
set(HEADER_FILES ${HEADER_FILES} PARENT_SCOPE)
