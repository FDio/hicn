FROM ubuntu:18.04 

ARG USERNAME=ubuntu
ARG USER_UID=1000
ARG USER_GID=$USER_UID

ARG VPP_GRP=vpp
ARG VPP_GID=998

ARG WORKDIR=/home/ubuntu

RUN apt-get update \
  && apt-get -y install --no-install-recommends apt-utils sudo dialog build-essential 	\
    cmake cppcheck valgrind curl autoconf automake ccache debhelper dkms git libtool  	\
    libapr1-dev dh-systemd libconfuse-dev git-review exuberant-ctags cscope pkg-config	\
    lcov chrpath autoconf indent clang-format libnuma-dev python-all python3-all      	\
    python3-setuptools python-dev python-virtualenv python-pip libffi6 check          	\
    libboost-all-dev libffi-dev python3-ply libmbedtls-dev  cmake ninja-build uuid-dev 	\
    python3-jsonschema gdb libssl-dev python-setuptools zsh 2>&1 						\
  #
  # Verify git, process tools, lsb-release (useful for CLI installs) installed
  && apt-get -y install git procps lsb-release curl iproute2 iperf3 \
  #
  # Create a non-root user to use if preferred - see https://aka.ms/vscode-remote/containers/non-root-user.
  && groupadd --gid $USER_GID $USERNAME \
  && useradd -s /bin/bash --uid $USER_UID --gid $USER_GID -m $USERNAME \
  # [Optional] Uncomment the next three lines to add sudo support
  && apt-get install -y sudo \
  && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
  && chmod 0440 /etc/sudoers.d/$USERNAME \
  # Create vpp group
  && groupadd --gid $VPP_GID $VPP_GRP \
  #
  && mkdir -p $WORKDIR \
  #
  # Clean up
  && apt-get autoremove -y \
  && apt-get clean -y \
  && rm -rf /var/lib/apt/lists/*

USER $USERNAME
COPY init.sh /init.sh

WORKDIR $WORKDIR

CMD ["bash", "/init.sh"]
