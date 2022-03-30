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

list(APPEND HEADER_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/probe_handler.h
  ${CMAKE_CURRENT_SOURCE_DIR}/rtc.h
  ${CMAKE_CURRENT_SOURCE_DIR}/rtc_consts.h
  ${CMAKE_CURRENT_SOURCE_DIR}/rtc_data_path.h
  ${CMAKE_CURRENT_SOURCE_DIR}/rtc_forwarding_strategy.h
  ${CMAKE_CURRENT_SOURCE_DIR}/rtc_indexer.h
  ${CMAKE_CURRENT_SOURCE_DIR}/rtc_ldr.h
  ${CMAKE_CURRENT_SOURCE_DIR}/rtc_packet.h
  ${CMAKE_CURRENT_SOURCE_DIR}/rtc_rc.h
  ${CMAKE_CURRENT_SOURCE_DIR}/rtc_rc_congestion_detection.h
  ${CMAKE_CURRENT_SOURCE_DIR}/rtc_rc_iat.h
  ${CMAKE_CURRENT_SOURCE_DIR}/rtc_rc_queue.h
  ${CMAKE_CURRENT_SOURCE_DIR}/rtc_reassembly.h
  ${CMAKE_CURRENT_SOURCE_DIR}/rtc_recovery_strategy.h
  ${CMAKE_CURRENT_SOURCE_DIR}/rtc_rs_delay.h
  ${CMAKE_CURRENT_SOURCE_DIR}/rtc_rs_fec_only.h
  ${CMAKE_CURRENT_SOURCE_DIR}/rtc_rs_low_rate.h
  ${CMAKE_CURRENT_SOURCE_DIR}/rtc_rs_recovery_off.h
  ${CMAKE_CURRENT_SOURCE_DIR}/rtc_rs_rtx_only.h
  ${CMAKE_CURRENT_SOURCE_DIR}/rtc_state.h
  ${CMAKE_CURRENT_SOURCE_DIR}/rtc_verifier.h
)

list(APPEND SOURCE_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/probe_handler.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/rtc.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/rtc_data_path.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/rtc_forwarding_strategy.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/rtc_ldr.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/rtc_rc_congestion_detection.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/rtc_rc_iat.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/rtc_rc_queue.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/rtc_reassembly.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/rtc_recovery_strategy.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/rtc_rs_delay.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/rtc_rs_fec_only.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/rtc_rs_low_rate.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/rtc_rs_recovery_off.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/rtc_rs_rtx_only.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/rtc_state.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/rtc_verifier.cc
)

set(SOURCE_FILES ${SOURCE_FILES} PARENT_SCOPE)
set(HEADER_FILES ${HEADER_FILES} PARENT_SCOPE)
