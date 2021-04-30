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

set(HICNPLUGIN_SEARCH_PATH_LIST
  ${VPP_SEARCH_PATH_LIST}
  ${HICNPLUGIN_HOME}
  $ENV{HICNPLUGIN_HOME}
  /usr/local
  /opt
  /usr
)

find_path(HICNPLUGIN_INCLUDE_DIR vapi/hicn.api.vapi.h
	HINTS ${HICNPLUGIN_SEARCH_PATH_LIST}
  PATH_SUFFIXES include
  DOC "Find the hicn plugin includes"
)


set(HICNPLUGIN_INCLUDE_DIRS ${HICNPLUGIN_INCLUDE_DIR} ${HICNPLUGIN_INCLUDE_DIR}/vpp_plugins)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(HicnPlugin DEFAULT_MSG HICNPLUGIN_INCLUDE_DIR)

mark_as_advanced(HICNPLUGIN_INCLUDE_DIR)