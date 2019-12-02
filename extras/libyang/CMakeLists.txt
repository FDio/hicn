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
cmake_minimum_required(VERSION 2.8)
project(libyang)

set(CMAKE_MODULE_PATH
  ${CMAKE_MODULE_PATH}
  "${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/Modules"
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules"
)

include(ExternalProject)
include(Packaging)

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
  set(LIBYANG libyang)
endif()

execute_process(
   COMMAND bash -c "if [ ! -d libyang ]; then
                    git clone  https://github.com/CESNET/libyang.git -b devel --depth 1 libyang;
                    cd libyang; git apply ${CMAKE_CURRENT_SOURCE_DIR}/libyang.patch;
                   else
                    pushd libyang && git pull && popd;
                   fi"
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

add_subdirectory(${CMAKE_CURRENT_BINARY_DIR}/libyang ${CMAKE_CURRENT_BINARY_DIR}/libyang)

include(Packaging)
if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    include(Packager)
    make_packages()
endif()