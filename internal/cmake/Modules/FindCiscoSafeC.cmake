# Copyright (c) 2017-2022 Cisco and/or its affiliates.
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
# Find the CiscoSafeC libraries and includes
# This module sets:
#  CISCOSAFEC_FOUND: True if CiscoSafeC was found
#  CISCOSAFEC_LIBRARY:  The CiscoSafeC library
#  CISCOSAFEC_LIBRARIES:  The CiscoSafeC library and dependencies
#  CISCOSAFEC_INCLUDE_DIR:  The CiscoSafeC include dir
#

set(CISCOSAFEC_SEARCH_PATH_LIST
  ${CISCOSAFEC_HOME}
  $ENV{CISCOSAFEC_HOME}
  /usr/local
  /opt
  /usr
)

find_path(CISCOSAFEC_INCLUDE_DIR safec_config.h
  HINTS ${CISCOSAFEC_SEARCH_PATH_LIST}
  PATH_SUFFIXES include include/safec
  DOC "Find the CiscoSafeC includes"
)

find_library(CISCOSAFEC_LIBRARY NAMES ciscosafec
  HINTS ${CISCOSAFEC_SEARCH_PATH_LIST}
  PATH_SUFFIXES lib
  DOC "Find the CiscoSafeC libraries"
)

set(CISCOSAFEC_LIBRARIES ${CISCOSAFEC_LIBRARY})
set(CISCOSAFEC_INCLUDE_DIRS ${CISCOSAFEC_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
set(CISCOSAFEC_FOUND False)

if (NOT "${CISCOSAFEC_INCLUDE_DIR}" STREQUAL "")
  set(CISCOSAFEC_FOUND True)
  find_package_handle_standard_args(CiscoSafeC DEFAULT_MSG CISCOSAFEC_LIBRARY CISCOSAFEC_INCLUDE_DIR)
  mark_as_advanced(CISCOSAFEC_LIBRARY CISCOSAFEC_INCLUDE_DIR)
endif ()
