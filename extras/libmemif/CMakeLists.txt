# Copyright (c) 2019 Cisco and/or its affiliates.
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

set(CMAKE_MODULE_PATH
  ${CMAKE_MODULE_PATH}
  "${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/Modules"
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules"
)

include(ExternalProject)
include(Packaging)

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
  set(LIBMEMIF memif)
endif()

execute_process(
  COMMAND bash -c "if [ ! -d vpp ]; then
                    git clone https://github.com/FDio/vpp.git -b stable/1908 --depth 1 vpp;
                   else
                    pushd vpp && git pull && popd;
                   fi"
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

execute_process(
  COMMAND ${CMAKE_COMMAND} -E
  remove_directory ${CMAKE_CURRENT_BINARY_DIR}/libmemif
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

execute_process(
  COMMAND ${CMAKE_COMMAND} -E
  copy_directory vpp/extras/libmemif ${CMAKE_CURRENT_BINARY_DIR}/libmemif
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

execute_process(
  COMMAND ${CMAKE_COMMAND} -E rename ${CMAKE_CURRENT_BINARY_DIR}/libmemif/src
          ${CMAKE_CURRENT_BINARY_DIR}/libmemif/memif
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

execute_process(
  COMMAND
  ${CMAKE_COMMAND} -E
  copy ${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists1.patch libmemif/CMakeLists.txt
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

execute_process(
  COMMAND ${CMAKE_COMMAND} -E
  copy ${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists2.patch libmemif/memif/CMakeLists.txt
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

include(Packaging)
add_subdirectory(${CMAKE_CURRENT_BINARY_DIR}/libmemif ${CMAKE_CURRENT_BINARY_DIR}/libmemif)