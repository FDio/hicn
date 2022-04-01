#!/bin/bash

# Copyright (c) 2022 Cisco and/or its affiliates.
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

set -euxo pipefail

################################################################
# Install defined VPP version
################################################################

VPP_VERSION=2202

if [[ -z ${VERSION_PATH-} ]]; then
  echo >&2 "No version path provided. Using version 22.02"
else
  VPP_VERSION=$(grep VPP_DEFAULT_VERSION "${VERSION_PATH}" | cut -d ' ' -f 2 | tr -d '"' | grep -Po '\d\d.\d\d')
  VPP_VERSION=${VPP_VERSION//./}
fi

# Prevent vpp to set sysctl
export VPP_INSTALL_SKIP_SYSCTL=1

curl -s https://packagecloud.io/install/repositories/fdio/${VPP_VERSION}/script.deb.sh | bash
curl -L https://packagecloud.io/fdio/${VPP_VERSION}/gpgkey | apt-key add -
sed -E -i 's/(deb.*)(\[.*\])(.*)/\1\3/g' /etc/apt/sources.list.d/fdio_"${VPP_VERSION}".list

# create apt pinning
cat << EOF | tee /etc/apt/preferences.d/vpp-pin
Package: vpp*
Pin: release o=packagecloud.io/fdio/${VPP_VERSION}
Pin-Priority: 1000

Package: libvpp*
Pin: release o=packagecloud.io/fdio/${VPP_VERSION}
Pin-Priority: 1000
EOF

apt-get update

apt-get install -y \
  vpp-dev \
  libvppinfra-dev \
  vpp-plugin-core \
  vpp \
  libvppinfra
