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

#############
# RPM/DEB/TGZ Packaging utils
#

set(CONTACT "hicn-dev@lists.fd.io" CACHE STRING "Contact")
set(PACKAGE_MAINTAINER "ICN Team" CACHE STRING "Maintainer")
set(PACKAGE_VENDOR "fd.io" CACHE STRING "Vendor")

function(get_next_version VERSION NEXT_VERSION)
  string(REGEX REPLACE "([0-9]+).([0-9]+)" "\\1;\\2" VER_NUMBERS ${VERSION})

  # Increment version for getting next version value
  list(GET VER_NUMBERS 0 major)
  list(GET VER_NUMBERS 1 minor)

  math(EXPR minor "${minor} + 3")

  if (minor GREATER 12)
    set(minor "1")
    math(EXPR major "${major} + 1")
  endif()

  if (minor LESS 10)
    set(minor "0${minor}")
  endif()

  set(${NEXT_VERSION} "${major}.${minor}" PARENT_SCOPE)
endfunction()

macro(extract_version)
  # Extract version from git
  execute_process(
    COMMAND git describe --long --match v*
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
    OUTPUT_VARIABLE VER
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )

  if (NOT VER)
    set(VER "v1.0-0-gcafe")
  endif()

  message(STATUS "Git describe output: ${VER}")

  string(REGEX REPLACE "v([0-9]+).([0-9]+)-([0-9]+)-(g[0-9a-f]+)" "\\1;\\2;\\3;\\4" VER ${VER})
  list(GET VER 0 VERSION_MAJOR)
  list(GET VER 1 VERSION_MINOR)
  list(GET VER 2 VERSION_REVISION)
  list(GET VER 3 COMMIT_NAME)
endmacro(extract_version)

macro(make_packages)
  if ("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
    # parse /etc/os-release
    file(READ "/etc/os-release" os_version)
    string(REPLACE "\n" ";" os_version ${os_version})
    foreach(_ver ${os_version})
      string(REPLACE "=" ";" _ver ${_ver})
      list(GET _ver 0 _name)
      list(GET _ver 1 _value)
      set(OS_${_name} ${_value})
    endforeach()

    extract_version()

    message(STATUS "Version major: ${VERSION_MAJOR}")
    message(STATUS "Version minor: ${VERSION_MINOR}")
    message(STATUS "Revision: ${VERSION_REVISION}")
    message(STATUS "Commit hash: ${COMMIT_NAME}")

    set(tag "${VERSION_MAJOR}.${VERSION_MINOR}")
    string(REPLACE "-" "~" tag ${tag})
    set(commit_num ${VERSION_REVISION})
    set(commit_name ${COMMIT_NAME})

    if (NOT DEFINED ENV{BUILD_NUMBER})
      set(bld "b1")
    else()
      set(bld "b$ENV{BUILD_NUMBER}")
    endif()

    message("Build number is: ${bld}")

    #define DEB and RPM version numbers
    if(${commit_num} EQUAL 0)
      set(deb_ver "${tag}")
      set(rpm_ver "${tag}")
    else()
      set(deb_ver "${tag}-${commit_num}-release")
      set(rpm_ver "${tag}-${commit_num}-release")
    endif()

    get_next_version(${tag} next_version)

    get_cmake_property(components COMPONENTS)
    get_cmake_property(CPACK_COMPONENTS_ALL COMPONENTS)

    if(OS_ID MATCHES "debian" OR OS_ID_LIKE MATCHES "debian")
      set(CPACK_GENERATOR "DEB")
      set(type "DEBIAN")

      execute_process(
        COMMAND dpkg --print-architecture
        OUTPUT_VARIABLE arch
        OUTPUT_STRIP_TRAILING_WHITESPACE
      )

      set(CPACK_PACKAGE_VERSION "${deb_ver}")
      foreach(lc ${components})
        if (${lc} MATCHES ".*Unspecified.*")
          continue()
        endif()

        string(TOUPPER ${lc} uc)
        set(CPACK_${type}_${uc}_FILE_NAME "${lc}_${deb_ver}_${arch}.deb")

        set(DEB_DEPS)
        if (NOT ${${lc}_DEB_DEPENDENCIES} STREQUAL "")
          string(REPLACE "stable_version" ${tag} DEB_DEPS ${${lc}_DEB_DEPENDENCIES})
          string(REPLACE "next_version" ${next_version} DEB_DEPS ${DEB_DEPS})
        endif()

        set(CPACK_${type}_${uc}_PACKAGE_DEPENDS "${DEB_DEPS}")
        set(CPACK_${type}_${uc}_PACKAGE_NAME "${lc}")
        set(CPACK_COMPONENT_${uc}_DESCRIPTION "${${lc}_DESCRIPTION}")

        if (${lc}_DEB_PACKAGE_CONTROL_EXTRA)
          set(CPACK_DEBIAN_${uc}_PACKAGE_CONTROL_EXTRA "${${lc}_DEB_PACKAGE_CONTROL_EXTRA}")
        endif()
      endforeach()
    elseif(OS_ID_LIKE MATCHES "rhel")
      set(CPACK_GENERATOR "RPM")
      set(type "RPM")

      execute_process(
        COMMAND uname -m
        OUTPUT_VARIABLE arch
        OUTPUT_STRIP_TRAILING_WHITESPACE
      )

      set(CPACK_PACKAGE_VERSION "${rpm_ver}")
      foreach(lc ${components})
        if (${lc} MATCHES ".*Unspecified.*")
          continue()
        endif()

        string(TOUPPER ${lc} uc)
        set(CPACK_${type}_${uc}_DESCRIPTION "${${lc}_DESCRIPTION}")

        set(RPM_DEPS)
        if (NOT ${${lc}_DEB_DEPENDENCIES} STREQUAL "")
          string(REPLACE "stable_version" ${tag} RPM_DEPS ${${lc}_RPM_DEPENDENCIES})
          string(REPLACE "next_version" ${next_version} RPM_DEPS ${RPM_DEPS})
        endif()

        set(CPACK_${type}_${uc}_PACKAGE_REQUIRES "${RPM_DEPS}")

        if(${lc} MATCHES ".*-dev")
          set(package_name ${lc}el)
        else()
          set(package_name ${lc})
        endif()

        set(CPACK_RPM_${uc}_PACKAGE_NAME "${package_name}")
        set(CPACK_${type}_${uc}_FILE_NAME "${package_name}-${rpm_ver}.${arch}.rpm")

        if (NOT ${${lc}_RPM_POST_INSTALL_SCRIPT_FILE} STREQUAL "")
          set(CPACK_RPM_${uc}_POST_INSTALL_SCRIPT_FILE "${${lc}_RPM_POST_INSTALL_SCRIPT_FILE}")
        endif()

        if (NOT ${${lc}_RPM_POST_UNINSTALL_SCRIPT_FILE} STREQUAL "")
          set(CPACK_RPM_${uc}_POST_UNINSTALL_SCRIPT_FILE "${${lc}_RPM_POST_UNINSTALL_SCRIPT_FILE}")
        endif()

        if (NOT ${${lc}_RPM_PRE_UNINSTALL_SCRIPT_FILE} STREQUAL "")
          set(CPACK_RPM_${uc}_PRE_UNINSTALL_SCRIPT_FILE "${${lc}_RPM_PRE_UNINSTALL_SCRIPT_FILE}")
        endif()
      endforeach()
    endif()

    if(CPACK_GENERATOR)
      set(CPACK_PACKAGE_NAME ${ARG_NAME})
      set(CPACK_STRIP_FILES OFF)
      set(CPACK_PACKAGE_VENDOR "${PACKAGE_VENDOR}")
      set(CPACK_COMPONENTS_IGNORE_GROUPS 1)
      set(CPACK_${CPACK_GENERATOR}_COMPONENT_INSTALL ON)
      set(CPACK_${type}_PACKAGE_MAINTAINER "HICN Team")
      set(CPACK_${type}_PACKAGE_RELEASE 1)
      include(CPack)
    endif()
  endif()
endmacro()
