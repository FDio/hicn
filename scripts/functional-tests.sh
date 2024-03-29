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

#!/bin/bash

set -euxo pipefail

SCRIPT_PATH=$( cd "$(dirname "${BASH_SOURCE}")" ; pwd -P )
source "${SCRIPT_PATH}/functions.sh"

echo "---------------------------------------------------------"
echo "-----  INSTALLING FUNCTIONAL TEST DEPENDENCIES  ---------"
echo "---------------------------------------------------------"

# This docker compose version is well supported also in CentOS.
# Versions >= 2.0.0 do not seem to work.
DOCKER_COMPOSE_VERSION=1.29.2

sudo curl -L "https://github.com/docker/compose/releases/download/${DOCKER_COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
sudo pip3 install robotframework

functional_test

exit 0
