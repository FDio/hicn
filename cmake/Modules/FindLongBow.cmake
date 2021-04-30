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
# Find the LongBow libraries and includes
# This module sets:
#  LONGBOW_FOUND: True if LongBow was found
#  LONGBOW_LIBRARY:  The LongBow library
#  LONGBOW_LIBRARIES:  The LongBow library and dependencies
#  LONGBOW_INCLUDE_DIR:  The LongBow include dir
#

set(LONGBOW_SEARCH_PATH_LIST
  ${LONGBOW_HOME}
  $ENV{LONGBOW_HOME}
  $ENV{PARC_HOME}
  $ENV{FOUNDATION_HOME}
  /usr/local/parc
  /usr/local/ccn
  /usr/local
  /opt
  /usr
  )

find_path(LONGBOW_INCLUDE_DIR LongBow/longBow_About.h
  HINTS ${LONGBOW_SEARCH_PATH_LIST}
  PATH_SUFFIXES include
  DOC "Find the LongBow includes" )

find_library(LONGBOW_LIBRARY NAMES longbow
  HINTS ${LONGBOW_SEARCH_PATH_LIST}
  PATH_SUFFIXES lib
  DOC "Find the LongBow libraries" )

find_library(LONGBOW_REPORT_LIBRARY NAMES longbow-textplain longbow-ansiterm
  HINTS ${LONGBOW_SEARCH_PATH_LIST}
  PATH_SUFFIXES lib
  DOC "Find the LongBow report libraries" )

set(LONGBOW_LIBRARIES ${LONGBOW_LIBRARY} ${LONGBOW_REPORT_LIBRARY})
set(LONGBOW_INCLUDE_DIRS ${LONGBOW_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LongBow  DEFAULT_MSG LONGBOW_LIBRARY LONGBOW_INCLUDE_DIR)
