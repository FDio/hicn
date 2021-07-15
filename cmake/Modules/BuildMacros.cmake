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

macro(remove_flag_from_target target flag)
    get_target_property(target_cxx_flags ${target} COMPILE_OPTIONS)
    if(target_cxx_flags)
        list(REMOVE_ITEM target_cxx_flags ${flag})
        set_target_properties(${target} PROPERTIES COMPILE_OPTIONS "${target_cxx_flags}")
    endif()
endmacro()

macro(build_executable exec)
  cmake_parse_arguments(ARG
    "NO_INSTALL"
    "COMPONENT"
    "SOURCES;LINK_LIBRARIES;DEPENDS;INCLUDE_DIRS;DEFINITIONS;COMPILE_OPTIONS;LINK_FLAGS"
    ${ARGN}
  )

  add_executable(${exec}-bin ${ARG_SOURCES})

  set(BUILD_ROOT ${CMAKE_BINARY_DIR}/build-root)

  set_target_properties(${exec}-bin
    PROPERTIES
    OUTPUT_NAME ${exec}
    INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}"
    BUILD_RPATH "${BUILD_ROOT}/lib"
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

  if (ARG_COMPILE_OPTIONS)
    target_compile_options(${exec}-bin PRIVATE -Wall -Werror ${ARG_COMPILE_OPTIONS})
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
    "SOURCES;LINK_LIBRARIES;OBJECT_LIBRARIES;LINK_FLAGS;INSTALL_HEADERS;DEPENDS;INCLUDE_DIRS;DEFINITIONS;HEADER_ROOT_DIR;LIBRARY_ROOT_DIR;INSTALL_FULL_PATH_DIR;EMPTY_PREFIX;COMPILE_OPTIONS;VERSION"
    ${ARGN}
  )

  message(STATUS "Building library ${lib}")

  # Clear target_libs
  unset(TARGET_LIBS)

  if (ARG_SHARED)
    list(APPEND TARGET_LIBS
      ${lib}.shared
    )
    add_library(${lib}.shared SHARED ${ARG_SOURCES} ${ARG_OBJECT_LIBRARIES})
  endif()

  if(ARG_STATIC)
    list(APPEND TARGET_LIBS
      ${lib}.static
    )
    add_library(${lib}.static STATIC ${ARG_SOURCES} ${ARG_OBJECT_LIBRARIES})
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
        BUILD_RPATH "${BUILD_ROOT}/lib"
        INSTALL_RPATH_USE_LINK_PATH TRUE
        PREFIX ""
        ARCHIVE_OUTPUT_DIRECTORY "${BUILD_ROOT}/lib"
        LIBRARY_OUTPUT_DIRECTORY "${BUILD_ROOT}/lib"
        RUNTIME_OUTPUT_DIRECTORY "${BUILD_ROOT}/bin"
        LINK_FLAGS "${ARG_LINK_FLAGS}"
      )
    else ()
      set_target_properties(${library}
        PROPERTIES
        INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}"
        BUILD_RPATH "${BUILD_ROOT}/lib"
        INSTALL_RPATH_USE_LINK_PATH TRUE
        ARCHIVE_OUTPUT_DIRECTORY "${BUILD_ROOT}/lib"
        LIBRARY_OUTPUT_DIRECTORY "${BUILD_ROOT}/lib"
        RUNTIME_OUTPUT_DIRECTORY "${BUILD_ROOT}/bin"
        LINK_FLAGS "${ARG_LINK_FLAGS}"
      )
    endif()

    if (WIN32)
      target_compile_options(${library} PRIVATE ${ARG_COMPILE_OPTIONS})
      set_target_properties(${library}
        PROPERTIES
        WINDOWS_EXPORT_ALL_SYMBOLS TRUE
      )
    else ()
      target_compile_options(${library}
        PRIVATE -Wall -Werror ${ARG_COMPILE_OPTIONS}
      )
      set_target_properties(${library}
        PROPERTIES
        OUTPUT_NAME ${lib}
      )
    endif ()

    # library deps
    if(ARG_LINK_LIBRARIES)
      target_link_libraries(${library} PUBLIC ${ARG_LINK_LIBRARIES})
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

    if(ARG_VERSION)
      set_target_properties(${library}
        PROPERTIES
        VERSION ${ARG_VERSION}
      )
    endif()

    set(INSTALL_LIB_PATH "${CMAKE_INSTALL_LIBDIR}/${ARG_LIBRARY_ROOT_DIR}")

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
    if (NOT ARG_HEADER_ROOT_DIR)
      set(ARG_HEADER_ROOT_DIR "hicn")
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
        if ("${dir}" STREQUAL ${ARG_HEADER_ROOT_DIR})
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
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${ARG_HEADER_ROOT_DIR}/${dir}
        COMPONENT ${COMPONENT}
      )
    endforeach()
  endif()
endmacro()

macro (build_module module)
  cmake_parse_arguments(ARG
    "SHARED;STATIC;NO_DEV"
    "COMPONENT;"
    "SOURCES;LINK_LIBRARIES;INSTALL_HEADERS;DEPENDS;INCLUDE_DIRS;DEFINITIONS;HEADER_ROOT_DIR;LIBRARY_ROOT_DIR;INSTALL_FULL_PATH_DIR;EMPTY_PREFIX;COMPILE_OPTIONS;VERSION"
    ${ARGN}
  )

  message(STATUS "Building module ${module}")

  build_library(${module}
    SHARED
    SOURCES ${ARG_SOURCES}
    LINK_LIBRARIES ${ARG_LINK_LIBRARIES}
    INSTALL_HEADERS ${ARG_INSTALL_HEADERS}
    DEPENDS ${ARG_DEPENDS}
    COMPONENT ${ARG_COMPONENT}
    INCLUDE_DIRS ${ARG_INCLUDE_DIRS}
    HEADER_ROOT_DIR ${ARG_HEADER_ROOT_DIR}
    LIBRARY_ROOT_DIR ${ARG_LIBRARY_ROOT_DIR}
    INSTALL_FULL_PATH_DIR ${ARG_INSTALL_FULL_PATH_DIR}
    DEFINITIONS ${ARG_DEFINITIONS}
    EMPTY_PREFIX ${ARG_EMPTY_PREFIX}
    COMPILE_OPTIONS ${ARG_COMPILE_OPTIONS}
    VERSION ${ARG_VERSION}
  )

  if (${CMAKE_SYSTEM_NAME} MATCHES Darwin)
    set(LINK_FLAGS "-Wl,-undefined,dynamic_lookup")
  elseif(${CMAKE_SYSTEM_NAME} MATCHES iOS)
    set(LINK_FLAGS "-Wl,-undefined,dynamic_lookup")
  elseif(${CMAKE_SYSTEM_NAME} MATCHES Linux)
    set(LINK_FLAGS "-Wl,-unresolved-symbols=ignore-all")
  elseif(${CMAKE_SYSTEM_NAME} MATCHES Windows)
    set(LINK_FLAGS "/wd4275")
  else()
    message(FATAL_ERROR "Trying to build module on a not supportd platform. Aborting.")
  endif()

  set_target_properties(${module}.shared
    PROPERTIES
    LINKER_LANGUAGE C
    PREFIX ""
    LINK_FLAGS ${LINK_FLAGS}
  )

endmacro(build_module)

include(IosMacros)
include(WindowsMacros)
