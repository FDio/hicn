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
# Find the LibTRANSPORT libraries and includes
# This module sets:
#  LIBTRANSPORT_FOUND: True if Libconsumer-producer was found
#  LIBTRANSPORTR_LIBRARY:  The Libconsumer-producer library
#  LIBTRANSPORT_LIBRARIES:  The Libconsumer-producer library and dependencies
#  LIBTRANSPORT_INCLUDE_DIR:  The Libconsumer-producer include dir
#

set(LIBTRANSPORT_SEARCH_PATH_LIST
  ${LIBTRANSPORT_HOME}
  $ENV{LIBTRANSPORTHOME}
  /usr/local
  /opt
  /usr
)

find_path(LIBTRANSPORT_INCLUDE_DIR hicn/transport/config.h
  HINTS ${LIBTRANSPORT_SEARCH_PATH_LIST}
  PATH_SUFFIXES include
  DOC "Find the libtransport includes"
)

find_library(LIBTRANSPORT_LIBRARY
  NAMES hicntransport hicntransport-memif
  HINTS ${LIBTRANSPORT_SEARCH_PATH_LIST}
  PATH_SUFFIXES lib
  DOC "Find the libtransport libraries"
)

set(LIBTRANSPORT_LIBRARIES ${LIBTRANSPORT_LIBRARY})
set(LIBTRANSPORT_INCLUDE_DIRS ${LIBTRANSPORT_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Libtransport DEFAULT_MSG LIBTRANSPORT_LIBRARIES LIBTRANSPORT_INCLUDE_DIRS)