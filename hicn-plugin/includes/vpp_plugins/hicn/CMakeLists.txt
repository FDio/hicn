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

include(GNUInstallDirs)

set(HICNPLUGIN_INCLUDE_DIRS
  ${CMAKE_CURRENT_SOURCE_DIR}/../..
  CACHE INTERNAL
  "" FORCE
)

set(HICNPLUGIN_TO_INSTALL_HEADER_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/error.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn_all_api_h.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn_api.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn_enums.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn_msg_enum.h ""
  CACHE INTERNAL
  "" FORCE
)