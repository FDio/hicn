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

if (VPP_LIBRARIES AND VPP_INCLUDE_DIRS)
  # in cache already
  set(VPP_FOUND TRUE)
else (VPP_LIBRARIES AND VPP_INCLUDE_DIRS)

  set(VPP_INCLUDE_PATH
    /usr/include
    /usr/local/include
    /opt/local/include
    /sw/include
  )

  set(VPP_LIBRARY_PATH
    /usr/lib
    /usr/lib64
    /usr/local/lib
    /usr/local/lib64
    /opt/local/lib
    /sw/lib
  )

  find_path(VNET_INCLUDE_DIR
    NAMES
      vnet/vnet.h
    PATHS
      ${VPP_INCLUDE_PATH}
      ${CMAKE_INCLUDE_PATH}
      ${CMAKE_INSTALL_PREFIX}/include
  )

  find_path(VLIB_API_INCLUDE_DIR
    NAMES
      vlibapi/api.h
    PATHS
      ${VPP_INCLUDE_PATH}
      ${CMAKE_INCLUDE_PATH}
      ${CMAKE_INSTALL_PREFIX}/include
  )

  find_path(VLIBMEMORY_INCLUDE_DIR
    NAMES
      vlibmemory/api.h
    PATHS
      ${VPP_INCLUDE_PATH}
      ${CMAKE_INCLUDE_PATH}
      ${CMAKE_INSTALL_PREFIX}/include
  )

  find_path(VPP_MSG_INCLUDE_DIR
    NAMES
      vpp/api/vpe_msg_enum.h
    PATHS
      ${VPP_INCLUDE_PATH}
      ${CMAKE_INCLUDE_PATH}
      ${CMAKE_INSTALL_PREFIX}/include
  )

  find_path(VPP_ALL_INCLUDE_DIR
    NAMES
      vpp/api/vpe_all_api_h.h
    PATHS
      ${VPP_INCLUDE_PATH}
      ${CMAKE_INCLUDE_PATH}
      ${CMAKE_INSTALL_PREFIX}/include
  )

  find_path(VAPI_INCLUDE_DIR
    NAMES
      vapi/interface.api.vapi.h
    PATHS
      ${VPP_INCLUDE_PATH}
      ${CMAKE_INCLUDE_PATH}
      ${CMAKE_INSTALL_PREFIX}/include
  )

  find_library(VLIBMEMORYCLIENT_LIBRARY
    NAMES
      vlibmemoryclient
      libvlibmemoryclient
    PATHS
      ${VPP_LIBARY_PATH}
      ${CMAKE_LIBRARY_PATH}
      ${CMAKE_INSTALL_PREFIX}/lib
  )

  find_library(SVM_LIBRARY
    NAMES
      svm
      libsvm
    PATHS
      ${VPP_LIBRARY_PATH}
      ${CMAKE_LIBRARY_PATH}
      ${CMAKE_INSTALL_PREFIX}/lib
  )

   find_library(VPPINFRA_LIBRARY
    NAMES
      vppinfra
      libvppinfra
    PATHS
      ${VPP_LIBRARY_PATH}
      ${CMAKE_LIBRARY_PATH}
      ${CMAKE_INSTALL_PREFIX}/lib
  )

   find_library(VLIB_LIBRARY
    NAMES
      vlib
      libvlib
    PATHS
      ${VPP_LIBRARY_PATH}
      ${CMAKE_LIBRARY_PATH}
      ${CMAKE_INSTALL_PREFIX}/lib
  )

   find_library(VATPLUGIN_LIBRARY
    NAMES
      vatplugin
      libvatplugin
    PATHS
      ${VPP_LIBRARY_PATH}
      ${CMAKE_LIBRARY_PATH}
      ${CMAKE_INSTALL_PREFIX}/lib
  )

   find_library(VAPI_LIBRARY
    NAMES
      vapiclient
      libvapiclient
    PATHS
      ${VPP_LIBRARY_PATH}
      ${CMAKE_LIBRARY_PATH}
      ${CMAKE_INSTALL_PREFIX}/lib
  )

  find_library(VOM_LIBRARY
    NAMES
      vom
      libvom
    PATHS
      ${VPP_LIBRARY_PATH}
      ${CMAKE_LIBRARY_PATH}
      ${CMAKE_INSTALL_PREFIX}/lib
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

  set(VPP_LIBRARIES
    ${VLIBMEMORYCLIENT_LIBRARY}
    ${SVM_LIBRARY}
    ${VPPINFRA_LIBRARY}
    ${VLIB_LIBRARY}
    ${VATPLUGIN_LIBRARY}
    ${VAPI_LIBRARY}
    ${VOM_LIBRARY}
  )

  # show the VPP_INCLUDE_DIRS and VPP_LIBRARIES variables only in the advanced view
  mark_as_advanced(VPP_INCLUDE_DIRS VPP_LIBRARIES)

endif (VPP_LIBRARIES AND VPP_INCLUDE_DIRS)