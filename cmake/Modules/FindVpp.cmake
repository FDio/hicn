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

set(VPP_SEARCH_PATH_LIST
  ${VPP_HOME}
  $ENV{VPP_HOME}
  /usr/local
  /opt
  /usr
)

find_path(VPP_INCLUDE_DIR vnet/vnet.h
  HINTS ${VPP_SEARCH_PATH_LIST}
  PATH_SUFFIXES include
  DOC "Find the VPP includes"
)

find_library(VPP_LIBRARY_MEMORYCLIENT
  NAMES vlibmemoryclient
  HINTS ${VPP_SEARCH_PATH_LIST}
  PATH_SUFFIXES lib lib64
  DOC "Find the Vpp Memoryclient library"
)

find_library(VPP_LIBRARY_SVM
  NAMES svm
  HINTS ${VPP_SEARCH_PATH_LIST}
  PATH_SUFFIXES lib lib64
  DOC "Find the Vpp svm library"
)

find_library(VPP_LIBRARY_INFRA
  NAMES vppinfra
  HINTS ${VPP_SEARCH_PATH_LIST}
  PATH_SUFFIXES lib lib64
  DOC "Find the Vpp infra library"
)

find_library(VPP_LIBRARY_VATPLUGIN
  NAMES vatplugin
  HINTS ${VPP_SEARCH_PATH_LIST}
  PATH_SUFFIXES lib lib64
  DOC "Find the Vpp vatplugin library"
)

find_library(VPP_LIBRARY_VLIB
  NAMES vlib
  HINTS ${VPP_SEARCH_PATH_LIST}
  PATH_SUFFIXES lib lib64
  DOC "Find the Vpp vlib library"
)

set(VPP_LIBRARIES ${VPP_LIBRARY_MEMORYCLIENT} ${VPP_LIBRARY_SVM} ${VPP_LIBRARY_INFRA} ${VPP_LIBRARY_VATPLUGIN} ${VPP_LIBRARY_VLIB})
set(VPP_INCLUDE_DIRS ${VPP_INCLUDE_DIR} ${VPP_INCLUDE_DIR}/vpp_plugins)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Vpp DEFAULT_MSG VPP_LIBRARIES VPP_INCLUDE_DIRS)