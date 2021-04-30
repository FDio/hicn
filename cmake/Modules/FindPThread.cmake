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

########################################
#
# Find the PThread libraries and includes
# This module sets:
#  PTHREAD_FOUND: True if pthread was found
#  PTHREADR_LIBRARY:  The pthread library
#  PTHREAD_LIBRARIES:  The pthread library and dependencies
#  PTHREAD_INCLUDE_DIR:  The pthread include dir
#


set(PTHREAD_SEARCH_PATH_LIST
  ${PTHREAD_HOME}
  $ENV{PTHREAD_HOME}
  /usr/local
  /opt
  /usr
)

find_path(PTHREAD_INCLUDE_DIR pthread.h
  HINTS ${PTHREAD_SEARCH_PATH_LIST}
  PATH_SUFFIXES include
  DOC "Find the pthreadincludes"
)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  find_library(PTHREAD_LIBRARY NAMES pthreadVC2.lib
    HINTS ${PTHREAD_SEARCH_PATH_LIST}
    PATH_SUFFIXES lib/x64
    DOC "Find the pthread libraries"
  )
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
  find_library(PTHREAD_LIBRARY NAMES pthreadVC2.lib
    HINTS ${PTHREAD_SEARCH_PATH_LIST}
    PATH_SUFFIXES lib/x32
    DOC "Find the pthread libraries"
  )
endif()


set(PTHREAD_LIBRARIES ${PTHREAD_LIBRARY})
set(PTHREAD_INCLUDE_DIRS ${PTHREAD_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Pthread DEFAULT_MSG PTHREAD_LIBRARIES PTHREAD_INCLUDE_DIRS)