# Copyright (c) 2020 Cisco and/or its affiliates.
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
# Find the Libblake3 libraries and includes
# This module sets:
#  LIBBLAKE3_FOUND: True if Libblake3 was found
#  LIBBLAKE3_LIBRARY:  The Libblake3 library
#  LIBBLAKE3_LIBRARIES:  The Libblake3 library and dependencies
#  LIBBLAKE3_INCLUDE_DIR:  The Libblake3 include dir
#

set(LIBBLAKE3_SEARCH_PATH_LIST
  ${LIBBLAKE3_HOME}
  $ENV{LIBBLAKE3_HOME}
  /usr/local
  /opt
  /usr
)

find_path(LIBBLAKE3_INCLUDE_DIR blake3/blake3.h
  HINTS ${LIBBLAKE3_SEARCH_PATH_LIST}
  PATH_SUFFIXES include
  DOC "Find the Libblake3 include"
)

find_library(LIBBLAKE3_LIBRARY NAMES blake3
  HINTS ${LIBBLAKE3_SEARCH_PATH_LIST}
  PATH_SUFFIXES lib
  DOC "Find the Libblake3 library"
)

set(LIBBLAKE3_LIBRARIES ${LIBBLAKE3_LIBRARY})
set(LIBBLAKE3_INCLUDE_DIRS ${LIBBLAKE3_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Libblake3 DEFAULT_MSG LIBBLAKE3_LIBRARY LIBBLAKE3_INCLUDE_DIR)

mark_as_advanced(LIBBLAKE3_LIBRARY LIBBLAKE3_INCLUDE_DIR)
