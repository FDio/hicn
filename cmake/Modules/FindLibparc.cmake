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
# Find the Libparc libraries and includes
# This module sets:
#  LIBPARC_FOUND: True if Libparc was found
#  LIBPARC_LIBRARY:  The Libparc library
#  LIBPARC_LIBRARIES:  The Libparc library and dependencies
#  LIBPARC_INCLUDE_DIR:  The Libparc include dir
#

set(LIBPARC_SEARCH_PATH_LIST
  ${LIBPARC_HOME}
  $ENV{LIBPARC_HOME}
  /usr/local
  /opt
  /usr
)

find_path(LIBPARC_INCLUDE_DIR parc/libparc_About.h
  HINTS ${LIBPARC_SEARCH_PATH_LIST}
  PATH_SUFFIXES include
  DOC "Find the Libparc includes"
)

find_library(LIBPARC_LIBRARY NAMES parc
  HINTS ${LIBPARC_SEARCH_PATH_LIST}
  PATH_SUFFIXES lib
  DOC "Find the Libparc libraries"
)

set(LIBPARC_LIBRARIES ${LIBPARC_LIBRARY})
set(LIBPARC_INCLUDE_DIRS ${LIBPARC_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Libparc DEFAULT_MSG LIBPARC_LIBRARY LIBPARC_INCLUDE_DIR)

mark_as_advanced(LIBPARC_LIBRARY LIBPARC_INCLUDE_DIR)
