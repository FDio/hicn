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

set(SYSREPO_SEARCH_PATH_LIST
  ${SYSREPO_HOME}
  $ENV{SYSREPO_HOME}
  /usr/local
  /opt
  /usr
)

find_path(SYSREPO_INCLUDE_DIR sysrepo/values.h
	HINTS ${SYSREPO_SEARCH_PATH_LIST}
  PATH_SUFFIXES include
  DOC "Find the sysrepo includes"
)

find_path(SYSREPO_INCLUDE_MAIN_DIR sysrepo.h
	HINTS ${SYSREPO_SEARCH_PATH_LIST}
  PATH_SUFFIXES include
  DOC "Find the sysrepo includes"
)

find_library(SYSREPO_LIBRARY NAMES libsysrepo.so
	HINTS ${SYSREPO_SEARCH_PATH_LIST}
    PATH_SUFFIXES lib
  DOC "Find the sysrepo library"
)

set(SYSREPO_LIBRARIES ${SYSREPO_LIBRARY})
set(SYSREPO_INCLUDE_DIRS ${SYSREPO_INCLUDE_DIR} ${SYSREPO_INCLUDE_MAIN_DIR})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Sysrepo DEFAULT_MSG SYSREPO_LIBRARIES SYSREPO_INCLUDE_DIRS)

mark_as_advanced(SYSREPO_LIBRARY SYSREPO_INCLUDE_DIR SYSREPO_INCLUDE_MAIN_DIR)
