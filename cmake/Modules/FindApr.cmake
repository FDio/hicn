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
#  APR_FOUND: True if apr was found
#  APR_INCLUDE_DIR:  The apr include dir
#

set(APR_SEARCH_PATH_LIST
  ${APR_HOME}
  $ENV{APR_HOME}
  /usr/local
  /opt
  /usr
  /usr/local/opt/apr/libexec
)

set(APR_PATH_SUFFIXES
  include/apr-1
  include/apr-1.0
)

###############
# libapr
###############

find_path(APR_INCLUDE_DIR apr.h
  HINTS ${APR_SEARCH_PATH_LIST}
  PATH_SUFFIXES ${APR_PATH_SUFFIXES}
  DOC "Find the apr includes"
)

find_library(APR_LIBRARY NAMES apr-1
  HINTS ${APR_SEARCH_PATH_LIST}
  PATH_SUFFIXES lib
  DOC "Find the apr lib"
)

###############
# libapr-util
###############

find_path(APRUTIL_INCLUDE_DIR apu.h
  HINTS ${APR_SEARCH_PATH_LIST}
  PATH_SUFFIXES ${APR_PATH_SUFFIXES}
  DOC "Find the apr includes"
)

find_library(APRUTIL_LIBRARY NAMES aprutil-1
  HINTS ${APR_SEARCH_PATH_LIST}
  PATH_SUFFIXES lib
  DOC "Find the apr lib"
)

set(APR_INCLUDE_DIRS ${APR_INCLUDE_DIR} ${APRUTIL_INCLUDE_DIR})
set(APR_LIBRARIES ${APR_LIBRARY} ${APRUTIL_LIBRARY})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(apr DEFAULT_MSG
  APR_INCLUDE_DIRS APR_LIBRARIES
)