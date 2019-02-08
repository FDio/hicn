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
# Find libgflags
#
#  LIBGFLAGS_INCLUDE_DIR - where to find gflags/gflags.h, etc.
#  LIBGFLAGS_LIBRARY     - List of libraries when using libgflags.
#  LIBGFLAGS_FOUND       - True if libgflags found.


IF (LIBGFLAGS_INCLUDE_DIR)
    # Already in cache, be silent
    SET(LIBGFLAGS_FIND_QUIETLY TRUE)
ENDIF ()

FIND_PATH(LIBGFLAGS_INCLUDE_DIR gflags/gflags.h)

FIND_LIBRARY(LIBGFLAGS_LIBRARY NAMES gflags gflags_static)

# handle the QUIETLY and REQUIRED arguments and set LIBGFLAGS_FOUND to TRUE if
# all listed variables are TRUE
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LIBGFLAGS DEFAULT_MSG LIBGFLAGS_LIBRARY LIBGFLAGS_INCLUDE_DIR)

MARK_AS_ADVANCED(LIBGFLAGS_LIBRARY LIBGFLAGS_INCLUDE_DIR)