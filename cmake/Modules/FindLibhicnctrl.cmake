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
# Find the hICN control library and include files
#

set(HICN_SEARCH_PATH_LIST
  ${HICN_HOME}
  $ENV{HICN_HOME}
  $ENV{FOUNDATION_HOME}
  /usr/local
  /opt
  /usr
)

find_path(LIBHICNCTRL_INCLUDE_DIR hicn/ctrl.h
  HINTS ${HICN_SEARCH_PATH_LIST}
  PATH_SUFFIXES include
  DOC "Find the hICN control include"
)

find_library(LIBHICNCTRL_LIBRARY NAMES hicnctrl
  HINTS ${HICN_SEARCH_PATH_LIST}
  PATH_SUFFIXES lib
  DOC "Find the hicn control library"
)

set(LIBHICNCTRL_LIBRARIES ${LIBHICNCTRL_LIBRARY})
set(LIBHICNCTRL_INCLUDE_DIRS ${LIBHICNCTRL_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(hicnctrl DEFAULT_MSG
        LIBHICNCTRL_LIBRARY LIBHICNCTRL_INCLUDE_DIR)
