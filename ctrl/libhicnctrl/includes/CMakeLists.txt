# Copyright (c) 2021-2022 Cisco and/or its affiliates.
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

##############################################################
# Public headers directory
##############################################################
set(Libhicnctrl_INCLUDE_DIRS
  ${CMAKE_CURRENT_SOURCE_DIR}
  CACHE INTERNAL
  "" FORCE
)


##############################################################
# To install header files
##############################################################
set(TO_INSTALL_HEADER_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/ctrl.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/ctrl/api.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/ctrl/action.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/ctrl/callback.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/ctrl/command.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/ctrl/data.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/ctrl/fw_interface.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/ctrl/hicn-light.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/ctrl/object.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/ctrl/object_type.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/ctrl/objects.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/ctrl/objects/active_interface.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/ctrl/objects/base.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/ctrl/objects/cache.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/ctrl/objects/connection.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/ctrl/objects/face.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/ctrl/objects/listener.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/ctrl/objects/mapme.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/ctrl/objects/policy.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/ctrl/objects/punting.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/ctrl/objects/route.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/ctrl/objects/strategy.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/ctrl/objects/subscription.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/ctrl/parse.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/ctrl/route.h
  ${CMAKE_CURRENT_SOURCE_DIR}/hicn/ctrl/socket.h
  PARENT_SCOPE
)
