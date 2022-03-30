#!/bin/bash

################################################################
# Install defined VPP version
################################################################

if [[ -z ${VERSION_PATH} ]]; then
  echo >&2 "No version path provided. Exit now."
  exit 1
fi

# Prevent vpp to set sysctl
export VPP_INSTALL_SKIP_SYSCTL=1
VPP_VERSION=$(cat "${VERSION_PATH}" | grep VPP_DEFAULT_VERSION | cut -d ' ' -f 2 | tr -d '"' | grep -Po '\d\d.\d\d')

curl -s https://packagecloud.io/install/repositories/fdio/${VPP_VERSION//./}/script.deb.sh | bash
curl -L https://packagecloud.io/fdio/${VPP_VERSION//./}/gpgkey | apt-key add -
sed -E -i 's/(deb.*)(\[.*\])(.*)/\1\3/g' /etc/apt/sources.list.d/fdio_${VPP_VERSION//./}.list

# create apt pinning
cat << EOF | tee /etc/apt/preferences.d/vpp-pin
Package: vpp*
Pin: release o=packagecloud.io/fdio/${VPP_VERSION//./}
Pin-Priority: 1000

Package: libvpp*
Pin: release o=packagecloud.io/fdio/${VPP_VERSION//./}
Pin-Priority: 1000
EOF

apt-get update

apt-get install -y \
  vpp-dev \
  libvppinfra-dev \
  vpp-plugin-core \
  vpp \
  libvppinfra
