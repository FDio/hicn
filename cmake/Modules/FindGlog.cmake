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

#
# Find libglog
#
#  LIBGLOG_INCLUDE_DIR - where to find glog/logging.h, etc.
#  LIBGLOG_LIBRARY     - List of libraries when using libglog.
#  LIBGLOG_FOUND       - True if libglog found.


IF (LIBGLOG_INCLUDE_DIR)
    # Already in cache, be silent
    SET(LIBGLOG_FIND_QUIETLY TRUE)
ENDIF ()

FIND_PATH(LIBGLOG_INCLUDE_DIR glog/logging.h)

FIND_LIBRARY(LIBGLOG_LIBRARY glog)

# handle the QUIETLY and REQUIRED arguments and set LIBGLOG_FOUND to TRUE if
# all listed variables are TRUE
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LIBGLOG DEFAULT_MSG LIBGLOG_LIBRARY LIBGLOG_INCLUDE_DIR)

MARK_AS_ADVANCED(LIBGLOG_LIBRARY LIBGLOG_INCLUDE_DIR)