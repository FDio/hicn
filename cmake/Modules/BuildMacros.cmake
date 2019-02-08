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

macro(build_executable exec)
  cmake_parse_arguments(ARG
    "NO_INSTALL"
    "COMPONENT"
    "SOURCES;LINK_LIBRARIES;DEPENDS;INCLUDE_DIRS;DEFINITIONS"
    ${ARGN}
  )

  set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")
  set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

  add_executable(${exec} ${ARG_SOURCES})
  if(ARG_LINK_LIBRARIES)
    target_link_libraries(${exec} ${ARG_LINK_LIBRARIES})
  endif()

  if(ARG_DEPENDS)
    add_dependencies(${exec} ${ARG_DEPENDS})
  endif()

  if(ARG_DEFINITIONS)
    target_compile_definitions(${exec} PRIVATE ${ARG_DEFINITIONS})
  endif()

  if(ARG_INCLUDE_DIRS)
    target_include_directories(${exec} BEFORE PUBLIC
      ${ARG_INCLUDE_DIRS}
      ${PROJECT_BINARY_DIR}
    )
  endif()

  if(NOT ARG_NO_INSTALL)
    install(TARGETS ${exec} DESTINATION bin COMPONENT ${ARG_COMPONENT})
  endif()
endmacro()

macro(build_library lib)
  cmake_parse_arguments(ARG
    "SHARED;STATIC"
    "COMPONENT;"
    "SOURCES;LINK_LIBRARIES;INSTALL_HEADERS;DEPENDS;INCLUDE_DIRS;DEFINITIONS;INSTALL_ROOT_DIR"
    ${ARGN}
  )

  set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")
  set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

  if (ARG_SHARED)
    list(APPEND TARGET_LIBS
      ${lib}.shared
    )
    add_library(${lib}.shared SHARED ${ARG_SOURCES})
  endif()

  if(ARG_STATIC)
    list(APPEND TARGET_LIBS
      ${lib}
    )
    add_library(${lib} STATIC ${ARG_SOURCES})
  endif()

      # install .so
  if(NOT ARG_COMPONENT)
    set(ARG_COMPONENT hicn)
  endif()

  foreach(library ${TARGET_LIBS})

    if (WIN32)
      target_compile_options(${library} PRIVATE)
    else ()
      target_compile_options(${library} PRIVATE -Wall)
    endif ()

    if(HICN_VERSION)
      set_target_properties(${library}
        PROPERTIES
        SOVERSION ${HICN_VERSION}
      )
    endif()

    set_target_properties(${library}
      PROPERTIES
      OUTPUT_NAME ${lib}
    )

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

    install(
      TARGETS ${library}
      DESTINATION lib
      COMPONENT ${ARG_COMPONENT}
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
      get_filename_component(dir ${_dir} NAME)
      if (${dir} STREQUAL src)
        set(dir "")
      endif()
      install(
        FILES ${file}
        DESTINATION include/${ARG_INSTALL_ROOT_DIR}/${dir}
        COMPONENT ${ARG_COMPONENT}-dev
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
