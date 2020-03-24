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
#  HICN_FOUND: True if hicn was found
#  HICN_LIBRARY:  The hicn library
#  HICN_LIBRARIES:  The hicn library and dependencies
#  HCIN_INCLUDE_DIR:  The hicn include dir
#

set(HICN_SEARCH_PATH_LIST
  ${HICN_HOME}
  $ENV{HICN_HOME}
  $ENV{FOUNDATION_HOME}
  /usr/local
  /opt
  /usr
)

find_path(HICN_INCLUDE_DIR hicn/hicn.h
  HINTS ${HICN_SEARCH_PATH_LIST}
  PATH_SUFFIXES include
  DOC "Find the hicn includes"
)

find_library(HICN_LIBRARY NAMES hicn
  HINTS ${HICN_SEARCH_PATH_LIST}
  PATH_SUFFIXES lib
  DOC "Find the hicn libraries"
)

set(HICN_LIBRARIES ${HICN_LIBRARY})
set(HICN_INCLUDE_DIRS ${HICN_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(hicn  DEFAULT_MSG HICN_LIBRARIES HICN_INCLUDE_DIRS)