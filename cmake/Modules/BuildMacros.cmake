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

##############################
# Utils for building libraries and executables
#

include(GNUInstallDirs)

macro(build_executable exec)
  cmake_parse_arguments(ARG
    "NO_INSTALL"
    "COMPONENT"
    "SOURCES;LINK_LIBRARIES;DEPENDS;INCLUDE_DIRS;DEFINITIONS;LINK_FLAGS"
    ${ARGN}
  )

  add_executable(${exec}-bin ${ARG_SOURCES})

  set(BUILD_ROOT ${CMAKE_BINARY_DIR}/build-root)

  set_target_properties(${exec}-bin
    PROPERTIES
    OUTPUT_NAME ${exec}
    INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}"
    INSTALL_RPATH_USE_LINK_PATH TRUE
    ARCHIVE_OUTPUT_DIRECTORY "${BUILD_ROOT}/lib"
    LIBRARY_OUTPUT_DIRECTORY "${BUILD_ROOT}/lib"
    RUNTIME_OUTPUT_DIRECTORY "${BUILD_ROOT}/bin"
    LINK_FLAGS "${ARG_LINK_FLAGS}"
  )

  if(ARG_LINK_LIBRARIES)
    target_link_libraries(${exec}-bin ${ARG_LINK_LIBRARIES})
  endif()

  if(ARG_DEPENDS)
    add_dependencies(${exec}-bin ${ARG_DEPENDS})
  endif()

  if(ARG_DEFINITIONS)
    target_compile_definitions(${exec}-bin PRIVATE ${ARG_DEFINITIONS})
  endif()

  if(ARG_INCLUDE_DIRS)
    target_include_directories(${exec}-bin BEFORE PUBLIC
      ${ARG_INCLUDE_DIRS}
      ${PROJECT_BINARY_DIR}
    )
  endif()

  if(NOT ARG_NO_INSTALL)
    install(
      TARGETS ${exec}-bin
      RUNTIME
      DESTINATION ${CMAKE_INSTALL_BINDIR}
      COMPONENT ${ARG_COMPONENT}
    )
  endif()
endmacro()

macro(build_library lib)
  cmake_parse_arguments(ARG
    "SHARED;STATIC;NO_DEV"
    "COMPONENT;"
    "SOURCES;LINK_LIBRARIES;INSTALL_HEADERS;DEPENDS;INCLUDE_DIRS;DEFINITIONS;INSTALL_ROOT_DIR;INSTALL_FULL_PATH_DIR;EMPTY_PREFIX;"
    ${ARGN}
  )

  if (ARG_SHARED)
    list(APPEND TARGET_LIBS
      ${lib}.shared
    )
    add_library(${lib}.shared SHARED ${ARG_SOURCES})
  endif()

  if(ARG_STATIC)
    list(APPEND TARGET_LIBS
      ${lib}.static
    )
    add_library(${lib}.static STATIC ${ARG_SOURCES})
  endif()

  if(NOT ARG_COMPONENT)
    set(ARG_COMPONENT hicn)
  endif()

  set(BUILD_ROOT ${CMAKE_BINARY_DIR}/build-root)

  foreach(library ${TARGET_LIBS})

    if(HICN_VERSION)
      set_target_properties(${library}
        PROPERTIES
        SOVERSION ${HICN_VERSION}
      )
    endif()

    if (${ARG_EMPTY_PREFIX})
      set_target_properties(${library}
        PROPERTIES
        INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}"
        INSTALL_RPATH_USE_LINK_PATH TRUE
        PREFIX ""
        ARCHIVE_OUTPUT_DIRECTORY "${BUILD_ROOT}/lib"
        LIBRARY_OUTPUT_DIRECTORY "${BUILD_ROOT}/lib"
        RUNTIME_OUTPUT_DIRECTORY "${BUILD_ROOT}/bin"
      )
    else ()
      set_target_properties(${library}
        PROPERTIES
        INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}"
        INSTALL_RPATH_USE_LINK_PATH TRUE
        ARCHIVE_OUTPUT_DIRECTORY "${BUILD_ROOT}/lib"
        LIBRARY_OUTPUT_DIRECTORY "${BUILD_ROOT}/lib"
        RUNTIME_OUTPUT_DIRECTORY "${BUILD_ROOT}/bin"
      )
    endif()

    if (WIN32)
      target_compile_options(${library} PRIVATE)
      set_target_properties(${library}
        PROPERTIES
        WINDOWS_EXPORT_ALL_SYMBOLS TRUE
      )
    else ()
      target_compile_options(${library} PRIVATE -Wall)
      set_target_properties(${library}
        PROPERTIES
        OUTPUT_NAME ${lib}
      )
    endif ()

    # library deps
    if(ARG_LINK_LIBRARIES)
      target_link_libraries(${library} ${ARG_LINK_LIBRARIES})
    endif()

    if(ARG_DEFINITIONS)
      target_compile_definitions(${library} PRIVATE ${ARG_DEFINITIONS})
    endif()

    if(ARG_INCLUDE_DIRS)
      target_include_directories(${library} BEFORE PUBLIC
        ${ARG_INCLUDE_DIRS}
        ${PROJECT_BINARY_DIR}
      )
    endif()

    set(INSTALL_LIB_PATH ${CMAKE_INSTALL_LIBDIR})

    if (ARG_INSTALL_FULL_PATH_DIR)
      set(INSTALL_LIB_PATH ${ARG_INSTALL_FULL_PATH_DIR})
    endif()

    install(
      TARGETS ${library}
      COMPONENT ${ARG_COMPONENT}
      RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
      ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
      LIBRARY DESTINATION ${INSTALL_LIB_PATH}
    )

    if(ARG_DEPENDS)
      add_dependencies(${library} ${ARG_DEPENDS})
    endif()
  endforeach()

  # install headers
  if(ARG_INSTALL_HEADERS)
    if (NOT ARG_INSTALL_ROOT_DIR)
      set(ARG_INSTALL_ROOT_DIR "hicn")
    endif()

    list(APPEND local_comps
      ${ARG_COMPONENT}-dev
    )

    foreach(file ${ARG_INSTALL_HEADERS})
      get_filename_component(_dir ${file} DIRECTORY)

      if (_dir)
        get_filename_component(dir ${_dir} NAME)
        if ("${dir}" STREQUAL src)
          set(dir "")
        endif()
        if ("${dir}" STREQUAL includes)
          set(dir "")
        endif()
        if ("${dir}" STREQUAL ${ARG_INSTALL_ROOT_DIR})
          set(dir "")
        endif()
      else()
        set(dir "")
      endif()

      set(COMPONENT ${ARG_COMPONENT})
      if (NOT ARG_NO_DEV)
        set(COMPONENT ${COMPONENT}-dev)
      endif()
      install(
        FILES ${file}
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${ARG_INSTALL_ROOT_DIR}/${dir}
        COMPONENT ${COMPONENT}
      )
    endforeach()
  endif()
endmacro()

add_custom_target(${PROJECT_NAME}_cleanup_profiling_data
  "find" "." "-name" "*.gcda" "-delete"
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  COMMENT "Cleanup previous profiling data."
)

macro(AddTest testFile)
  add_executable(${ARGV0} ${ARGV0}.cc)
  target_link_libraries(${ARGV0} ${TARGET_TRANSPORT_STATIC} ${GTEST_LIBRARIES})
  add_test(${ARGV0} ${ARGV0})
  set_target_properties(${ARGV0} PROPERTIES FOLDER Test)
  add_dependencies(${ARGV0} ${PROJECT_NAME}_cleanup_profiling_data)
endmacro(AddTest)

include(IosMacros)
include(WindowsMacros)
