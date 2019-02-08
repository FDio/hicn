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

set(HICN_BINARY_API_SEARCH_PATH_LIST
  ${HICN_BINARY_API_HOME}
  $ENV{HICN_BINARY_API_HOME}
  /usr/local
  /opt
  /usr
)

find_path(HICN_BINARY_API_INCLUDE_DIR vpp_plugins/hicn/hicn_api.h
  HINTS ${VPP_SEARCH_PATH_LIST}
  PATH_SUFFIXES include
  DOC "Find the VPP includes"
)

set(HICN_BINARY_API_INCLUDE_DIRS ${VPP_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(HicnBinaryApi DEFAULT_MSG VPP_LIBRARIES VPP_INCLUDE_DIRS)