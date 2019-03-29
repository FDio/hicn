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

#if (VPP_LIBRARIES AND VPP_INCLUDE_DIRS)
  # in cache already
#  set(VPP_FOUND TRUE)
#else (VPP_LIBRARIES AND VPP_INCLUDE_DIRS)

set(VPP_SEARCH_PATH_LIST
#    ${VPP_HOME}
#    $ENV{VPP_HOME}
    /usr/lib
    /usr/lib64
    /usr/local/lib
    /usr/local/lib64
    /opt/local/lib
    /sw/lib
    /usr/local
    /opt
    /usr)

#  set(VPP_INCLUDE_PATH
#    /usr/include
#    /usr/local/include
#    /opt/local/include
#    /sw/include
#  )

#  set(VPP_LIBRARY_PATH
#    /usr/lib
#    /usr/lib64
#    /usr/local/lib
#    /usr/local/lib64
#    /opt/local/lib
#    /sw/lib
#  )

  find_path(VNET_INCLUDE_DIR
    NAMES
      vnet/vnet.h
    HINTS
      ${VPP_SEARCH_PATH_LIST}
    PATH_SUFFIXES include
  )

  find_path(VLIB_API_INCLUDE_DIR
    NAMES
      vlibapi/api.h
    HINTS
      ${VPP_SEARCH_PATH_LIST}
    PATH_SUFFIXES include
  )

  find_path(VLIBMEMORY_INCLUDE_DIR
    NAMES
      vlibmemory/api.h
    HINTS
      ${VPP_SEARCH_PATH_LIST}
    PATH_SUFFIXES include
  )

  find_path(VPP_MSG_INCLUDE_DIR
    NAMES
      vpp/api/vpe_msg_enum.h
    HINTS
      ${VPP_SEARCH_PATH_LIST}
    PATH_SUFFIXES include
  )

  find_path(VPP_ALL_INCLUDE_DIR
    NAMES
      vpp/api/vpe_all_api_h.h
    HINTS
      ${VPP_SEARCH_PATH_LIST}
    PATH_SUFFIXES include
  )

  find_path(VAPI_INCLUDE_DIR
    NAMES
      vapi/interface.api.vapi.h
    HINTS
      ${VPP_SEARCH_PATH_LIST}
    PATH_SUFFIXES include
  )

  find_library(VLIBMEMORYCLIENT_LIBRARY
    NAMES
      vlibmemoryclient
      libvlibmemoryclient
    HINTS
      ${VPP_SEARCH_PATH_LIST}
    PATH_SUFFIXES lib lib64
  )

  find_library(SVM_LIBRARY
    NAMES
      svm
      libsvm
    HINTS
      ${VPP_SEARCH_PATH_LIST}
    PATH_SUFFIXES lib lib64
  )

   find_library(VPPINFRA_LIBRARY
    NAMES
      vppinfra
      libvppinfra
    HINTS
      ${VPP_SEARCH_PATH_LIST}
    PATH_SUFFIXES lib lib64
  )

   find_library(VLIB_LIBRARY
    NAMES
      vlib
      libvlib
    HINTS
      ${VPP_SEARCH_PATH_LIST}
    PATH_SUFFIXES lib lib64
  )

   find_library(VATPLUGIN_LIBRARY
    NAMES
      vatplugin
      libvatplugin
    HINTS
      ${VPP_SEARCH_PATH_LIST}
    PATH_SUFFIXES lib lib64
  )

   find_library(VAPI_LIBRARY
    NAMES
      vapiclient
      libvapiclient
    HINTS
      ${VPP_SEARCH_PATH_LIST}
    PATH_SUFFIXES lib lib64
  )

  if (VPP_INCLUDE_DIR AND VPP_LIBRARY)
    set(VPP_FOUND TRUE)
  else (VPP_INCLUDE_DIR AND VPP_LIBRARY)
    set(VPP_FOUND FALSE)
  endif (VPP_INCLUDE_DIR AND VPP_LIBRARY)

  set(VPP_INCLUDE_DIRS
    ${VNET_INCLUDE_DIR}
    ${VLIB_API_INCLUDE_DIR}
    ${VLIB_MEMORY_INCLUDE_DIR}
    ${VPP_MSG_INCLUDE_DIR}
    ${VPP_ALL_INCLUDE_DIR}
    ${VAPI_INCLUDE_DIR}
  )

message(${VAPI_LIBRARY})
  set(VPP_LIBRARIES
    ${VLIBMEMORYCLIENT_LIBRARY}
    ${SVM_LIBRARY}
    ${VPPINFRA_LIBRARY}
    ${VLIB_LIBRARY}
    ${VATPLUGIN_LIBRARY}
    ${VAPI_LIBRARY}
  )

  # show the VPP_INCLUDE_DIRS and VPP_LIBRARIES variables only in the advanced view
  mark_as_advanced(VPP_INCLUDE_DIRS VPP_LIBRARIES)

#endif (VPP_LIBRARIES AND VPP_INCLUDE_DIRS)
