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
  ${CMAKE_CURRENT_SOURCE_DIR}/not_implemented_exception.h
  ${CMAKE_CURRENT_SOURCE_DIR}/invalid_ip_address_exception.h
  ${CMAKE_CURRENT_SOURCE_DIR}/malformed_name_exception.h
  ${CMAKE_CURRENT_SOURCE_DIR}/errors.h
  ${CMAKE_CURRENT_SOURCE_DIR}/malformed_packet_exception.h
  ${CMAKE_CURRENT_SOURCE_DIR}/runtime_exception.h
  ${CMAKE_CURRENT_SOURCE_DIR}/tokenizer_exception.h
  ${CMAKE_CURRENT_SOURCE_DIR}/null_pointer_exception.h
  ${CMAKE_CURRENT_SOURCE_DIR}/malformed_ahpacket_exception.h
  ${CMAKE_CURRENT_SOURCE_DIR}/unexpected_manifest_exception.h
  ${CMAKE_CURRENT_SOURCE_DIR}/indexing_exception.h
)

set(HEADER_FILES ${HEADER_FILES} PARENT_SCOPE)