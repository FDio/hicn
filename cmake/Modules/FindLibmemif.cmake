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
#  LIBMEMIF_FOUND: True if core was found
#  LIBMEMIF_LIBRARY:  The core library
#  LIBMEMIF_INCLUDE_DIR:  The core include dir
#

set(LIBMEMIF_SEARCH_PATH_LIST
  ${LIBMEMIF_HOME}
  $ENV{LIBMEMIF_HOME}
  /usr/local
  /opt
  /usr
)

find_path(LIBMEMIF_INCLUDE_DIR memif/libmemif.h
  HINTS ${LIBMEMIF_SEARCH_PATH_LIST}
  PATH_SUFFIXES include
  DOC "Find the libmemif includes"
)

find_library(LIBMEMIF_LIBRARY NAMES memif
  HINTS ${LIBMEMIF_SEARCH_PATH_LIST}
  PATH_SUFFIXES lib
  DOC "Find the libmemif libraries"
)

set(LIBMEMIF_LIBRARIES ${LIBMEMIF_LIBRARY})
set(LIBMEMIF_INCLUDE_DIRS ${LIBMEMIF_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Libmemif DEFAULT_MSG LIBMEMIF_LIBRARY LIBMEMIF_INCLUDE_DIR)
