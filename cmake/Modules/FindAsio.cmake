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

########################################
#
# Find the hcin libraries and includes
# This module sets:
#  ASIO_FOUND: True if asio was found
#  ASIO_INCLUDE_DIR:  The asio include dir
#

set(ASIO_SEARCH_PATH_LIST
  ${ASIO_HOME}
  $ENV{ASIO_HOME}
  /usr/local
  /opt
  /usr
)

find_path(ASIO_INCLUDE_DIR asio.hpp
  HINTS ${ASIO_SEARCH_PATH_LIST}
  PATH_SUFFIXES include
  DOC "Find the asio includes"
)

set(ASIO_INCLUDE_DIRS ${ASIO_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Asio
  REQUIRED_VARS ASIO_INCLUDE_DIRS
)