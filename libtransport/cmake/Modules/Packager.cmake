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

# Generate DEB / RPM packages

# Default variables

if (NOT DEFINED ENV{VENDOR})
  set(VENDOR "Cisco Systems" CACHE STRING "Vendor")
else ()
  set(VENDOR ENV{VENDOR} CACHE STRING "Vendor")
endif ()

if (NOT DEFINED ENV{CONTACT})
  set(CONTACT "msardara@cisco.com" CACHE STRING "Contact")
else ()
  set(CONTACT ENV{CONTACT} CACHE STRING "Contact")
endif()

if (NOT DEFINED ENV{PACKAGE_MAINTAINER})
  set(PACKAGE_MAINTAINER "Mauro Sardara (msardara@cisco.com)" CACHE STRING "Maintainer")
else ()
  set(PACKAGE_MAINTAINER ENV{PACKAGE_MAINTAINER} CACHE STRING "Maintainer")
endif()

if (NOT DEFINED ENV{CPACK_PACKAGING_INSTALL_PREFIX})
  set(CPACK_PACKAGING_INSTALL_PREFIX "/usr")
else ()
  set(CPACK_PACKAGING_INSTALL_PREFIX ENV{CPACK_PACKAGING_INSTALL_PREFIX})
endif()

set(CPACK_COMPONENTS_ALL library headers utils documentation)

function (make_package_internal PACKAGE_NAME PACKAGE_VERSION ARCHITECTURE GENERATOR TYPE DESCRIPTION HOMEPAGE)
  set(CPACK_GENERATOR ${GENERATOR})
  set(CPACK_PACKAGE_VENDOR ${VENDOR})
  set(CPACK_PACKAGE_CONTACT ${CONTACT})

  set(CPACK_${GENERATOR}_COMPONENT_INSTALL ON)
  set(CPACK_${TYPE}_PACKAGE_MAINTAINER ${PACKAGE_MAINTAINER})
  set(CPACK_${TYPE}_PACKAGE_NAME ${PACKAGE_NAME})
  set(CPACK_${TYPE}_PACKAGE_VERSION ${PACKAGE_VERSION})
  set(CPACK_${TYPE}_PACKAGE_ARCHITECTURE ${ARCHITECTURE})
  set(CPACK_${TYPE}_PACKAGE_RELEASE 1)
  set(CPACK_${TYPE}_PACKAGE_VENDOR ${VENDOR})
  set(CPACK_${TYPE}_PACKAGE_DESCRIPTION ${DESCRIPTION})
  set(CPACK_${TYPE}_PACKAGE_HOMEPAGE ${HOMEPAGE})

  include(CPack)
endfunction()

function(make_deb_package PACKAGE_NAME PACKAGE_VERSION ARCHITECTURE DEPS BUILD_DEPS DESCRIPTION HOMEPAGE)

  set(TYPE "DEBIAN")
  set(GENERATOR "DEB")

  set(CPACK_${TYPE}_LIBRARY_PACKAGE_NAME "${PACKAGE_NAME}")
  set(CPACK_${TYPE}_UTILS_PACKAGE_NAME "${PACKAGE_NAME}-utils")
  set(CPACK_${TYPE}_HEADERS_PACKAGE_NAME "${PACKAGE_NAME}-dev")
  set(CPACK_${TYPE}_DOCUMENTATION_PACKAGE_NAME "${PACKAGE_NAME}-doc")

  set(CPACK_${TYPE}_LIBRARY_FILE_NAME "${CPACK_${TYPE}_LIBRARY_PACKAGE_NAME}_${PACKAGE_VERSION}_${ARCHITECTURE}.deb")
  set(CPACK_${TYPE}_UTILS_FILE_NAME "${CPACK_${TYPE}_UTILS_PACKAGE_NAME}_${PACKAGE_VERSION}_${ARCHITECTURE}.deb")
  set(CPACK_${TYPE}_HEADERS_FILE_NAME "${CPACK_${TYPE}_HEADERS_PACKAGE_NAME}_${PACKAGE_VERSION}_${ARCHITECTURE}.deb")
  set(CPACK_${TYPE}_DOCUMENTATION_FILE_NAME "${CPACK_${TYPE}_DOCUMENTATION_PACKAGE_NAME}_${PACKAGE_VERSION}_${ARCHITECTURE}.deb")

  set(CPACK_DEBIAN_LIBRARY_PACKAGE_SHLIBDEPS OFF)

  set(CPACK_${TYPE}_LIBRARY_PACKAGE_DEPENDS ${DEPS})
  set(CPACK_${TYPE}_UTILS_PACKAGE_DEPENDS ${CPACK_${TYPE}_LIBRARY_PACKAGE_NAME})
  set(CPACK_${TYPE}_HEADERS_PACKAGE_DEPENDS ${BUILD_DEPS})
  set(CPACK_${TYPE}_DOCUMENTATION_PACKAGE_DEPENDS "")

  make_package_internal(${PACKAGE_NAME} ${PACKAGE_VERSION} ${ARCHITECTURE} ${GENERATOR} ${TYPE} ${DESCRIPTION} ${HOMEPAGE})
endfunction()

function(make_rpm_package PACKAGE_NAME PACKAGE_VERSION ARCHITECTURE DEPS BUILD_DEPS DESCRIPTION HOMEPAGE)
  set(TYPE "RPM")
  set(GENERATOR "RPM")

  set(CPACK_${TYPE}_LIBRARY_PACKAGE_NAME "${PACKAGE_NAME}")
  set(CPACK_${TYPE}_UTILS_PACKAGE_NAME "${PACKAGE_NAME}-utils")
  set(CPACK_${TYPE}_HEADERS_PACKAGE_NAME "${PACKAGE_NAME}-devel")
  set(CPACK_${TYPE}_DOCUMENTATION_PACKAGE_NAME "${PACKAGE_NAME}-doc")

  set(CPACK_${TYPE}_LIBRARY_FILE_NAME "${CPACK_${TYPE}_LIBRARY_PACKAGE_NAME}-${PACKAGE_VERSION}.${ARCHITECTURE}.rpm")
  set(CPACK_${TYPE}_LIBRARY_FILE_NAME "${CPACK_${TYPE}_UTILS_PACKAGE_NAME}-${PACKAGE_VERSION}.${ARCHITECTURE}.rpm")
  set(CPACK_${TYPE}_HEADERS_FILE_NAME "${CPACK_${TYPE}_HEADERS_PACKAGE_NAME}-${PACKAGE_VERSION}.${ARCHITECTURE}.rpm")
  set(CPACK_${TYPE}_DOCUMENTATION_FILE_NAME "${CPACK_${TYPE}_DOCUMENTATION_PACKAGE_NAME}-${PACKAGE_VERSION}.${ARCHITECTURE}.rpm")

  set(CPACK_${TYPE}_LIBRARY_PACKAGE_AUTOREQ OFF)

  set(CPACK_${TYPE}_LIBRARY_PACKAGE_REQUIRES ${DEPS})
  set(CPACK_${TYPE}_UTILS_PACKAGE_DEPENDS ${CPACK_${TYPE}_LIBRARY_PACKAGE_NAME})
  set(CPACK_${TYPE}_HEADERS_PACKAGE_REQUIRES ${BUILD_DEPS})
  set(CPACK_${TYPE}_DOCUMENTATION_PACKAGE_REQUIRES "")

  set(CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "/usr/etc" "/usr/lib/python2.7" "/usr/lib/python2.7/site-packages")

  make_package_internal(${PACKAGE_NAME} ${PACKAGE_VERSION} ${ARCHITECTURE} ${GENERATOR} ${TYPE} ${DESCRIPTION} ${HOMEPAGE})
endfunction()

function(make_tgz_package PACKAGE_NAME PACKAGE_VERSION ARCHITECTURE)

  set(TYPE "ARCHIVE")
  set(GENERATOR "TGZ")

  set(CPACK_${TYPE}_COMPONENT_INSTALL ON)
  set(CPACK_${TYPE}_LIBRARY_FILE_NAME "${PACKAGE_NAME}_${PACKAGE_VERSION}_${ARCHITECTURE}")
  set(CPACK_${TYPE}_UTILS_FILE_NAME "${PACKAGE_NAME}-utils_${PACKAGE_VERSION}_${ARCHITECTURE}")
  set(CPACK_${TYPE}_HEADERS_FILE_NAME "${PACKAGE_NAME}-dev_${PACKAGE_VERSION}_${ARCHITECTURE}")
  set(CPACK_${TYPE}_DOCUMENTATION_FILE_NAME "${PACKAGE_NAME}-doc_${PACKAGE_VERSION}_${ARCHITECTURE}")

  set(CPACK_GENERATOR ${GENERATOR})
  set(CPACK_PACKAGE_VENDOR ${VENDOR})
  set(CPACK_PACKAGE_CONTACT ${CONTACT})

  include(CPack)

endfunction()

function (make_package DEPS_DEB DEPS_RPM BUILD_DEPS_DEB BUILD_DEPS_RPM DESCRIPTION HOMEPAGE)

  if (NOT DEFINED ENV{PACKAGE_NAME})
    string(TOLOWER ${CMAKE_PROJECT_NAME} PACKAGE_NAME)
  else ()
    string(TOLOWER $ENV{PACKAGE_NAME} PACKAGE_NAME)
  endif ()

  # Get the version
  execute_process(COMMAND bash ${CMAKE_SOURCE_DIR}/scripts/version
    OUTPUT_VARIABLE PACKAGE_VERSION)

  if (PACKAGE_VERSION)
    string(STRIP ${PACKAGE_VERSION} PACKAGE_VERSION)
  else ()
    set(PACKAGE_VERSION 1.0)
  endif ()

  if (EXISTS "/etc/lsb-release")
    execute_process(COMMAND grep -oP "(?<=DISTRIB_ID=).*" /etc/lsb-release OUTPUT_VARIABLE DISTRIB_ID)
    execute_process(COMMAND grep -oP "(?<=DISTRIB_RELEASE=).*" /etc/lsb-release OUTPUT_VARIABLE DISTRIB_RELEASE)
    execute_process(COMMAND grep -oP "(?<=DISTRIB_CODENAME=).*" /etc/lsb-release OUTPUT_VARIABLE DISTRIB_CODENAME)
    execute_process(COMMAND grep -oP "(?<=DISTRIB_DESCRIPTION=).*" /etc/lsb-release OUTPUT_VARIABLE DISTRIB_DESCRIPTION)
    execute_process(COMMAND uname -m COMMAND tr -d '\n' OUTPUT_VARIABLE ARCHITECTURE)

    if (${ARCHITECTURE} STREQUAL "x86_64")
      set(ARCHITECTURE "amd64")
    endif()

    make_deb_package(${PACKAGE_NAME}
                     ${PACKAGE_VERSION}
                     ${ARCHITECTURE}
                     ${DEPS_DEB}
                     ${BUILD_DEPS_DEB}
                     ${DESCRIPTION}
                     ${HOMEPAGE})

  elseif(EXISTS "/etc/redhat-release")
    execute_process(COMMAND sudo yum install -y redhat-lsb)
    execute_process(COMMAND lsb_release -si OUTPUT_VARIABLE DISTRIB_ID)
    execute_process(COMMAND lsb_release -sr OUTPUT_VARIABLE DISTRIB_RELEASE)
    execute_process(COMMAND lsb_release -sc OUTPUT_VARIABLE DISTRIB_CODENAME)
    execute_process(COMMAND lsb_release -sd OUTPUT_VARIABLE DISTRIB_DESCRIPTION)
    execute_process(COMMAND uname -m -m COMMAND tr -d '\n' OUTPUT_VARIABLE ARCHITECTURE)

    make_rpm_package(${PACKAGE_NAME}
                     ${PACKAGE_VERSION}
                     ${ARCHITECTURE}
                     ${DEPS_RPM}
                     ${BUILD_DEPS_RPM}
                     ${DESCRIPTION}
                     ${HOMEPAGE})
  else()
    execute_process(COMMAND uname -m COMMAND tr -d '\n' OUTPUT_VARIABLE ARCHITECTURE)

    if (${ARCHITECTURE} STREQUAL "x86_64")
      set(ARCHITECTURE "amd64")
    endif()
  
    # Other linux system. Create a tar.gz package
    make_tgz_package(${PACKAGE_NAME}
                     ${PACKAGE_VERSION}
                     ${ARCHITECTURE})

  endif()
endfunction()
