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

if (WIN32)

else ()
  find_package(Libparc)
  message("CommonDependencies!!!!!")
  if ( NOT LIBPARC_FOUND )
    ExternalProject_Add(libparc
      GIT_REPOSITORY https://github.com/FDio/cicn.git
      GIT_TAG cframework/master
      PREFIX ${CMAKE_CURRENT_BINARY_DIR}
      CONFIGURE_COMMAND COMMAND cmake ${CMAKE_CURRENT_BINARY_DIR}/src/libparc/libparc/CMakeLists.txt -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl/  -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX}
      BUILD_COMMAND COMMAND make ${CMAKE_CURRENT_BINARY_DIR}
      INSTALL_COMMAND COMMAND make -j install
      BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/src/libparc/libparc
    )
    #include_directories(${CMAKE_INSTALL_PREFIX}/include)
    set(LIBPARC_LIBRARIES "${CMAKE_INSTALL_PREFIX}/lib/libparc.dylib")
    set(LIBPARC_INCLUDE_DIRS "${CMAKE_INSTALL_PREFIX}/include")
    set(LIBPARC_FOUND true)
  endif ()
endif ()