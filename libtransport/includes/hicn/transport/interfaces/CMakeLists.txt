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
  ${CMAKE_CURRENT_SOURCE_DIR}/socket_consumer.h
  ${CMAKE_CURRENT_SOURCE_DIR}/socket_producer.h
  ${CMAKE_CURRENT_SOURCE_DIR}/publication_options.h
  ${CMAKE_CURRENT_SOURCE_DIR}/socket_options_default_values.h
  ${CMAKE_CURRENT_SOURCE_DIR}/socket_options_keys.h
  ${CMAKE_CURRENT_SOURCE_DIR}/callbacks.h
  ${CMAKE_CURRENT_SOURCE_DIR}/global_conf_interface.h
  ${CMAKE_CURRENT_SOURCE_DIR}/statistics.h
  ${CMAKE_CURRENT_SOURCE_DIR}/portal.h
  ${CMAKE_CURRENT_SOURCE_DIR}/notification.h
)

set(HEADER_FILES ${HEADER_FILES} PARENT_SCOPE)
