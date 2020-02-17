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

set(SAFE_VAPI_SEARCH_PATH_LIST
  ${SAFE_VAPI_HOME}
  $ENV{SAFE_VAPI_HOME}
  /usr/local
  /opt
  /usr
)

find_path(SAFE_VAPI_INCLUDE_DIR vapi/vapi_safe.h
	HINTS ${SAFE_VAPI_SEARCH_PATH_LIST}
  PATH_SUFFIXES include
  DOC "Find the vapi_safe includes"
)

find_library(SAFE_VAPI_LIBRARY NAMES libsafe_vapi.so
	HINTS ${SAFE_VAPI_SEARCH_PATH_LIST}
  PATH_SUFFIXES lib/x86_64-linux-gnu/
  DOC "Find the vapi safe lib"
)

set(SAFE_VAPI_LIBRARIES ${SAFE_VAPI_LIBRARY})
set(SAFE_VAPI_INCLUDE_DIRS ${SAFE_VAPI_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(VapiSafe DEFAULT_MSG SAFE_VAPI_LIBRARIES SAFE_VAPI_INCLUDE_DIRS)

mark_as_advanced(SAFE_VAPI_LIBRARY SAFE_VAPI_INCLUDE_DIR)
