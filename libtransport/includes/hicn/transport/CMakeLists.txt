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

set(ASIO_STANDALONE 1)

add_subdirectory(core)
add_subdirectory(errors)
add_subdirectory(http)
add_subdirectory(interfaces)
add_subdirectory(portability)
add_subdirectory(auth)
add_subdirectory(utils)


##############################################################
# Public headers directory
##############################################################
set(Libhicntransport_INCLUDE_DIRS
  ${CMAKE_CURRENT_SOURCE_DIR}/../..
  CACHE INTERNAL
  "" FORCE
)


##############################################################
# Header files to install
##############################################################
set(LIBHICNTRANSPORT_TO_INSTALL_HEADER_FILES
  ${HEADER_FILES}
  PARENT_SCOPE
)
