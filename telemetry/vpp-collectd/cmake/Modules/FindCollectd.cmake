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

set(COLLECTD_SEARCH_PATH_LIST
  ${COLLECTD_HOME}
  $ENV{COLLECTD_HOME}
  /usr/local
  /opt
  /usr
)

find_path(COLLECTD_INCLUDE_DIR daemon/collectd.h
	HINTS ${HICNPLUGIN_SEARCH_PATH_LIST}
  PATH_SUFFIXES include/collectd/core/
  DOC "Find the collectd includes"
)


set(COLLECTD_INCLUDE_DIRS ${COLLECTD_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Collectd DEFAULT_MSG COLLECTD_INCLUDE_DIRS)

mark_as_advanced(COLLECTD_INCLUDE_DIRS)