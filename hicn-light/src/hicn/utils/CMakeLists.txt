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

# XXX This is installed in hicn/utils...
list(APPEND HEADER_FILES
#  ${CMAKE_CURRENT_SOURCE_DIR}/commands.h
#  ${CMAKE_CURRENT_SOURCE_DIR}/interface.h
#  ${CMAKE_CURRENT_SOURCE_DIR}/interfaceSet.h
  ${CMAKE_CURRENT_SOURCE_DIR}/punting.h
  ${CMAKE_CURRENT_SOURCE_DIR}/token.h
)

list(APPEND SOURCE_FILES
#  ${CMAKE_CURRENT_SOURCE_DIR}/interface.c
#  ${CMAKE_CURRENT_SOURCE_DIR}/interfaceSet.c
  ${CMAKE_CURRENT_SOURCE_DIR}/punting.c
)

set(SOURCE_FILES ${SOURCE_FILES} PARENT_SCOPE)
set(HEADER_FILES ${HEADER_FILES} PARENT_SCOPE)
