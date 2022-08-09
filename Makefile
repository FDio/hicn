# Copyright (c) 2021-2022 Cisco and/or its affiliates.
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


export WS_ROOT=$(CURDIR)
SHELL := /usr/bin/env bash
FUNCTIONAL := tests/run-functional.sh
MKDIR := mkdir -p
RM := rm
VERSIONFILE := $(CURDIR)/versions.cmake

# Docker stuff
DOCKER := docker
DEV_IMAGE := hicn-dev-img
DOCKERFILE := Dockerfile.dev
DEV_CONTAINER := hicn-dev

#
# OS Detection
#
ifeq ($(shell uname),Darwin)
OS_ID = macos
OPENSSL_ROOT=/usr/local/opt/openssl@1.1
else
OS_ID         = $(shell grep '^ID=' /etc/os-release | cut -f2- -d= | sed -e 's/\"//g')
OS_VERSION_ID = $(shell grep '^VERSION_ID=' /etc/os-release | cut -f2- -d= | sed -e 's/\"//g')
endif

ifeq ($(shell uname),Darwin)
BUILD_HICNPLUGIN := OFF
PUNTING := OFF
else
BUILD_HICNPLUGIN := ON
PUNTING := ON
endif

DEB_DEPENDS  = cmake ninja-build unzip python3-ply libasio-dev
DEB_DEPENDS += libconfig-dev libconfig++-dev libevent-dev
DEB_DEPENDS += build-essential vpp-dev libvppinfra-dev
DEB_DEPENDS += vpp-plugin-core libcurl4-openssl-dev libssl-dev
DEB_DEPENDS += doxygen

DEBUG_DEPENDS = iproute2 iperf3 iputils-ping tcpdump gdb

MACOS_DEPENDS = asio libconfig ninja openssl@1.1

.PHONY = help
help:
	@echo "Targets"
	@echo " dep                 - install software dependencies"
	@echo " debug-tools         - install debug dependencies"
	@echo " build               - build debug binaries. Optional argument: INSTALL_DIR"
	@echo " build-release       - build release binaries"
	@echo " build-coverage      - build with coverage metainformation"
	@echo " wipe                - wipe debug binaries"
	@echo " wipe-release        - wipe release binaries"
	@echo " docs                - build documentation"
	@echo ""
	@echo "Make Arguments:"
	@echo " INSTALL_PREFIX=<path>   	- Install software at specified location."
	@echo " BUILD_PATH=<path>   		- Path of build folder."
	@echo " VPP_HOME=<path>         	- Path of VPP"
	@echo " OPENSSL_ROOT=<path>         	- Path of Openssl installation"
	@echo " ENABLE_RELY=<ON/OFF>         	- Enable/disable rely compilation"
	@echo " SONAR_BUILD_WRAPPER=<path>"	- Path of sonarqube build wrapper
	@echo " SONAR_OUT_DIR=<path>"		- Path of directory of sonarqube report
	@echo "Current Arguments:"
	@echo " INSTALL_PREFIX=$(INSTALL_PREFIX)"
	@echo " VPP_HOME=$(VPP_HOME)"
	@echo " OPENSSL_ROOT=$(OPENSSL_ROOT)"
	@echo " ENABLE_RELY=$(ENABLE_RELY)"
	@echo " SONAR_BUILD_WRAPPER=$(SONAR_BUILD_WRAPPER)"
	@echo " SONAR_OUT_DIR=$(SONAR_OUT_DIR)"

.PHONY = vpp-dep
vpp-dep:
	VERSION_PATH=$(VERSIONFILE) sudo -E $(SHELL) scripts/install-vpp.sh

.PHONY = dep
dep: vpp-dep
ifeq ($(shell uname),Darwin)
	brew install $(MACOS_DEPENDS)
else ifeq ($(filter ubuntu debian,$(OS_ID)),$(OS_ID))
	@sudo -E apt-get update
	@sudo -E apt-get $(APT_ARGS) -y install $(DEB_DEPENDS) --no-install-recommends
else
	@echo "Operating system not supported (yet)"
endif

.PHONY = deps
deps: dep

.PHONY = debug-tools
debug-tools:
	@sudo -E apt-get $(APT_ARGS) -y install $(DEBUG_DEPENDS) --no-install-recommends

define build_folder
	$(eval LOWER_BUILDTYPE=$(shell echo $(2) | tr A-Z a-z))
	$(eval BUILD_FOLDER=$(or $(BUILD_PATH), build-$(LOWER_BUILDTYPE)-$(OS_ID)))
	$(1) := $$(BUILD_FOLDER)
endef

define configure
	$(eval $(call build_folder,BUILD_FOLDER,$(1)))
	$(eval PREFIX=$(or $(INSTALL_PREFIX), $(WS_ROOT)/install-$(LOWER_BUILDTYPE)))
	$(eval COVERAGE=$(or $(COVERAGE), OFF))
	$(eval VPP_HOME=$(or $(VPP_HOME), /usr))
	$(eval ENABLE_RELY=$(or $(ENABLE_RELY), OFF))
	$(MKDIR) $(BUILD_FOLDER)
	cmake \
		-B $(BUILD_FOLDER) \
		-S $(WS_ROOT) \
		-G Ninja \
		-DCMAKE_INSTALL_PREFIX=$(PREFIX) \
		-DCMAKE_BUILD_TYPE=$(1) \
		-DBUILD_HICNLIGHT=ON \
		-DBUILD_APPS=ON \
		-DBUILD_SYSREPOPLUGIN=OFF \
		-DBUILD_EXTRAS=OFF \
		-DBUILD_TELEMETRY=OFF \
		-DBUILD_CTRL=ON \
		-DBUILD_HICNPLUGIN=$(BUILD_HICNPLUGIN) \
		-DVPP_HOME=$(VPP_HOME) \
		-DCOVERAGE=$(COVERAGE) \
		-DENABLE_RELY=$(ENABLE_RELY) \
		-DOPENSSL_ROOT_DIR=$(OPENSSL_ROOT) \
		-DBUILD_TESTS=ON
endef

define build
	$(eval $(call build_folder,BUILD_FOLDER,$(1)))
	cmake --build $(BUILD_FOLDER) -- -j 4 install
endef

define build_coverage
	$(eval $(call build_folder,BUILD_FOLDER,$(1)))
	$(eval SONAR_OUT_DIR=$(or $(SONAR_OUT_DIR), $(WS_ROOT)/sonarqube-output))
	$(SONAR_BUILD_WRAPPER) --out-dir $(SONAR_OUT_DIR) cmake --build $(BUILD_FOLDER) -- install
endef

define package
	$(eval $(call build_folder,BUILD_FOLDER,$(1)))
	cmake --build $(BUILD_FOLDER) -- package
endef

.PHONY: configure-debug
configure-debug:
	$(call configure,Debug,)

.PHONY: configure-release
configure-release:
	$(call configure,Release,)

.PHONY = build
build: configure-debug
	$(call build,Debug,)

.PHONY = build-coverage
build-coverage:
ifndef SONAR_BUILD_WRAPPER
	$(error SONAR_BUILD_WRAPPER is not set)
endif
	$(eval COVERAGE := ON)
	$(call configure,Debug,)
	$(call build_coverage,Debug,)

.PHONY = build-release
build-release: configure-release
	$(call build,Release,)

.PHONY = package
package: build
	$(call package,Debug,)

.PHONY = package-release
package-release: build-release
	$(call package,Release,)

define wipe
	$(eval LOWER_BUILDTYPE=$(shell echo $(1) | tr A-Z a-z))
	$(RM) -rf build-$(LOWER_BUILDTYPE)-$(OS_ID)
	$(RM) -rf install-$(LOWER_BUILDTYPE)
endef

.PHONY = wipe
wipe:
	$(call wipe,Debug,)

.PHONY = wipe-release
wipe-release:
	$(call wipe,Release,)

define test
	$(eval $(call build_folder,BUILD_FOLDER,$(1)))
	cmake --build $(BUILD_FOLDER) -- test
endef

.PHONY = test-debug
test-debug: build
	$(call test, Debug,)

.PHONY = test
test: build-release
	$(call test, Release,)

.PHONY = functional
functional:
	$(SHELL) $(FUNCTIONAL)

define documentation
	python3 -m pip install --user virtualenv
	python3 -m virtualenv env
	(source $(WS_ROOT)/env/bin/activate; \
	pip install -r $(WS_ROOT)/docs/etc/requirements.txt; \
	cd docs; \
	make html )
endef

.PHONY = doc
doc:
	$(call documentation,)


.PHONY = docker
docker:
	$(DOCKER) build -t $(DEV_IMAGE) -f $(DOCKERFILE) ${PWD}
ifeq ($(strip $(shell $(DOCKER) ps -q -f name=$(DEV_CONTAINER))),)
ifneq ($(shell $(DOCKER) ps -aq -f status=exited -f name=$(DEV_CONTAINER)),)
	docker rm $(DEV_CONTAINER)
endif
	$(DOCKER) run -dv ${PWD}:/workspace -w /workspace --name $(DEV_CONTAINER) --entrypoint=tail $(DEV_IMAGE) -f /dev/null
endif
	$(DOCKER) exec -it $(DEV_CONTAINER) bash

.PHONY = wipe-docker
wipe-docker:
	$(DOCKER) rm --force $(DEV_CONTAINER)