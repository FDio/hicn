# Copyright (c) 2019 Cisco and/or its affiliates.
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

set(HICNLIGHT_SEARCH_PATH_LIST
  ${HICNLIGHT_HOME}
  $ENV{HICNLIGHT_HOME}
  /usr/local
  /opt
  /usr
)

find_path(HICNLIGHT_INCLUDE_DIR hicn/ctrl/api.h
	HINTS ${HICNLIGHT_SEARCH_PATH_LIST}
  PATH_SUFFIXES include
  DOC "Find the hicn plugin includes"
)

find_library(HICNLIGHT_LIBRARY NAMES libhicnctrl.so
	HINTS ${HICNLIGHT_SEARCH_PATH_LIST}
  PATH_SUFFIXES lib/x86_64-linux-gnu/
  DOC "Find the hicn light lib"
)

set(HICNLIGHT_LIBRARIES ${HICNLIGHT_LIBRARY})
set(HICNLIGHT_INCLUDE_DIRS ${HICNLIGHT_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Hicnlight HICNLIGHT_LIBRARIES HICNLIGHT_INCLUDE_DIRS)

mark_as_advanced(HICNLIGHT_LIBRARY HICNLIGHT_INCLUDE_DIR)
