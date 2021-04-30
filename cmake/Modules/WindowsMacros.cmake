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

if(WIN32)
  find_package(LibEvent REQUIRED)
  find_package(OpenSSL REQUIRED)
  find_package(PThread REQUIRED)
  find_library(WSOCK32_LIBRARY wsock32 required)
  find_library(WS2_32_LIBRARY ws2_32 required)
  list(APPEND WINDOWS_LIBRARIES
    ${LIBEVENT_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${PTHREAD_LIBRARIES}
    ${WSOCK32_LIBRARY}
    ${WS2_32_LIBRARY}
  )

  list(APPEND WINDOWS_INCLUDE_DIRS
    ${LIBEVENT_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
    ${PTHREAD_INCLUDE_DIRS}
  )
endif()