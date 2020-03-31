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

cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

list(APPEND HEADER_FILES
#  ${CMAKE_CURRENT_SOURCE_DIR}/commandOps.h
#  ${CMAKE_CURRENT_SOURCE_DIR}/commandParser.h
${CMAKE_CURRENT_SOURCE_DIR}/configuration.h
#  ${CMAKE_CURRENT_SOURCE_DIR}/commandReturn.h
#  ${CMAKE_CURRENT_SOURCE_DIR}/symbolicNameTable.h
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlState.h
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlRoot.h
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlAddConnection.h
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlAdd.h
#  ${CMAKE_CURRENT_SOURCE_DIR}/configuration_file.h
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlAddRoute.h
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlAddPolicy.h
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlAddListener.h
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlListConnections.h
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlList.h
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlListListeners.h
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlListRoutes.h
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlListPolicies.h
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlQuit.h
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlRemove.h
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlRemoveListener.h
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlRemoveConnection.h
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlRemoveRoute.h
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlRemovePolicy.h
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlSet.h
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlUnset.h
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlSetDebug.h
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlUnsetDebug.h
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlMapMe.h
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlMapMeEnable.h
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlMapMeDiscovery.h
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlMapMeTimescale.h
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlCacheServe.h
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlCacheStore.h
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlCacheClear.h
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlCache.h
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlSetStrategy.h
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlSetWldr.h
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlAddPunting.h
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlRemovePunting.h
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlUpdate.h
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlUpdateConnection.h
)

list(APPEND SOURCE_FILES
#  ${CMAKE_CURRENT_SOURCE_DIR}/commandOps.c
#  ${CMAKE_CURRENT_SOURCE_DIR}/commandParser.c
  ${CMAKE_CURRENT_SOURCE_DIR}/configuration.c
  ${CMAKE_CURRENT_SOURCE_DIR}/configuration_file.c
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlState.c
#  ${CMAKE_CURRENT_SOURCE_DIR}/symbolicNameTable.c
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlAdd.c
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlAddConnection.c
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlAddRoute.c
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlAddPolicy.c
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlAddListener.c
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlList.c
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlListConnections.c
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlListListeners.c
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlListRoutes.c
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlListPolicies.c
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlQuit.c
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlRemove.c
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlRemoveListener.c
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlRemoveConnection.c
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlRemoveRoute.c
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlRemovePolicy.c
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlRoot.c
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlSet.c
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlSetDebug.c
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlUnset.c
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlUnsetDebug.c
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlMapMe.c
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlMapMeEnable.c
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlMapMeDiscovery.c
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlMapMeTimescale.c
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlMapMeRetx.c
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlCacheServe.c
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlCacheStore.c
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlCacheClear.c
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlCache.c
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlSetStrategy.c
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlSetWldr.c
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlAddPunting.c
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlRemovePunting.c
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlUpdate.c
#  ${CMAKE_CURRENT_SOURCE_DIR}/controlUpdateConnection.c
)

set(SOURCE_FILES ${SOURCE_FILES} PARENT_SCOPE)
set(HEADER_FILES ${HEADER_FILES} PARENT_SCOPE)
