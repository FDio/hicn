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
  ${CMAKE_CURRENT_SOURCE_DIR}/facade.h
  ${CMAKE_CURRENT_SOURCE_DIR}/manifest.h
  ${CMAKE_CURRENT_SOURCE_DIR}/manifest_format_fixed.h
  ${CMAKE_CURRENT_SOURCE_DIR}/manifest_format.h
  ${CMAKE_CURRENT_SOURCE_DIR}/pending_interest.h
  ${CMAKE_CURRENT_SOURCE_DIR}/portal.h
  ${CMAKE_CURRENT_SOURCE_DIR}/errors.h
  ${CMAKE_CURRENT_SOURCE_DIR}/global_configuration.h
  ${CMAKE_CURRENT_SOURCE_DIR}/global_id_counter.h
  ${CMAKE_CURRENT_SOURCE_DIR}/local_connector.h
  ${CMAKE_CURRENT_SOURCE_DIR}/global_workers.h
  ${CMAKE_CURRENT_SOURCE_DIR}/udp_connector.h
  ${CMAKE_CURRENT_SOURCE_DIR}/udp_listener.h
  ${CMAKE_CURRENT_SOURCE_DIR}/global_module_manager.h
)

list(APPEND SOURCE_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/content_object.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/interest.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/errors.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/packet.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/name.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/prefix.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/manifest_format_fixed.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/portal.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/global_configuration.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/io_module.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/udp_connector.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/udp_listener.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/constructor.cc
)

if (NOT ${CMAKE_SYSTEM_NAME} MATCHES Android)
  if (UNIX AND NOT APPLE)
    list(APPEND SOURCE_FILES
      ${CMAKE_CURRENT_SOURCE_DIR}/memif_connector.cc
    )

    list(APPEND HEADER_FILES
      ${CMAKE_CURRENT_SOURCE_DIR}/memif_connector.h
    )
  endif()
endif()

set(SOURCE_FILES ${SOURCE_FILES} PARENT_SCOPE)
set(HEADER_FILES ${HEADER_FILES} PARENT_SCOPE)
