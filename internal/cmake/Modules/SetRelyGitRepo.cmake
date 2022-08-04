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

macro(SetRelyGitRepo)
    if(DEFINED ENV{BITBUCKET_USERNAME} AND DEFINED ENV{BITBUCKET_PASSWORD})
        set(GIT_REPO https://$ENV{BITBUCKET_USERNAME}:$ENV{BITBUCKET_PASSWORD}@bitbucket-eng-gpk1.cisco.com/bitbucket/scm/icn/rely.git)
    else()
        set(GIT_REPO ssh://git@bitbucket-eng-gpk1.cisco.com:7999/icn/rely.git)
    endif()
endmacro()