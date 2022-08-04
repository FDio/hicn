# Copyright (c) 2017-2022 Cisco and/or its affiliates.
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

macro(ImportInternal)
    find_package(CiscoSafeC)
    if (CiscoSafeC_FOUND)
    list(APPEND COMPILER_DEFINITIONS
        "-DENABLE_SAFEC"
    )
    list(APPEND THIRD_PARTY_LIBRARIES ${CISCOSAFEC_LIBRARY})
    list(APPEND THIRD_PARTY_INCLUDE_DIRS ${CISCOSAFEC_INCLUDE_DIR})
    endif()
endmacro()