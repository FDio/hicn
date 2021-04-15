FROM dockerhub.cisco.com/icn-docker/hicn-devel-focal:x86_64 as intermediate

WORKDIR /hicn-build

# Copy current hicn repo
COPY . ./hicn

WORKDIR /hicn-build/build-hicn

RUN cmake                           \
  -G Ninja                          \
  -DCMAKE_INSTALL_PREFIX=/hicn-root \
  -DENABLE_PUNTING=OFF              \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DBUILD_HICNLIGHT=ON              \
  -DBUILD_APPS=ON                   \
  -DBUILD_SYSREPOPLUGIN=OFF         \
  -DBUILD_EXTRAS=OFF                \
  -DBUILD_TELEMETRY=OFF             \
  -DBUILD_CTRL=ON                   \
  -DBUILD_HICNPLUGIN=ON             \
  -DBUILD_TESTS=ON                  \
  ../hicn

# Build project
RUN cmake --build .

# Run tests
RUN cmake --build . -- test || true

# Install
RUN cmake --build . -- install

FROM dockerhub.cisco.com/icn-docker/hicn-prod-focal:x86_64

# Copy hicn-root folder
COPY --from=intermediate /hicn-root /hicn-root

# Modify vpp config filr in order to fing the hicn plugin
ENV VPP_CONFIG="/etc/vpp/startup.conf"
COPY docker/startup.conf ${VPP_CONFIG}

WORKDIR /

ENTRYPOINT ["sudo", "/usr/bin/dumb-init", "/usr/bin/vpp", "-c", "/etc/vpp/startup.conf"]
