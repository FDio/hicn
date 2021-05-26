function(change_rpath LIB_PATH TYPE)
    execute_process (
        COMMAND bash -c "ls ${LIB_PATH}"
        OUTPUT_VARIABLE ITEMS
    )
    string(REPLACE "\n" ";" ITEMS ${ITEMS})

    separate_arguments(ITEMS)
    foreach (ITEM ${ITEMS})
        if (NOT ITEM MATCHES ".a$")
            if (TYPE STREQUAL "LIB")
                execute_process (
                    COMMAND bash -c "otool -L ${LIB_PATH}/${ITEM} | head -2 | tail -1| sed -e 's/^[[:space:]]*//'|awk '{print $1;}'" 
                    OUTPUT_VARIABLE OTOOL_OUTPUT
                )
                string(REPLACE "\n" "" OTOOL_OUTPUT ${OTOOL_OUTPUT})

                execute_process (
                    COMMAND bash -c "basename ${OTOOL_OUTPUT}| sed -e 's/^[[:space:]]*//'" 
                    OUTPUT_VARIABLE BASENAME
                )
                string(REPLACE "\n" "" BASENAME ${BASENAME})
                execute_process (
                        COMMAND bash -c "install_name_tool -id ${CPACK_INSTALL_PREFIX}/${BASENAME} ${LIB_PATH}/${ITEM}"
                        OUTPUT_VARIABLE OUTPUT_INSTALL_NAME_TOOL
                    )
                #change rpath
                execute_process (
                    COMMAND bash -c "otool -L ${LIB_PATH}/${ITEM} | tail -n +3| sed -e 's/^[[:space:]]*//'|awk '{print $1;}'"
                    OUTPUT_VARIABLE OTOOL_OUTPUTS
                )
            else ()
                #change rpath
                execute_process (
                    COMMAND bash -c "otool -L ${LIB_PATH}/${ITEM} | tail -n +2| sed -e 's/^[[:space:]]*//'|awk '{print $1;}'"
                    OUTPUT_VARIABLE OTOOL_OUTPUTS
                )
            endif ()
            string(REPLACE "\n" ";" OTOOL_OUTPUTS ${OTOOL_OUTPUTS})
            separate_arguments(OTOOL_OUTPUTS)
            foreach (OTOOL_OUTPUT ${OTOOL_OUTPUTS})
                execute_process (
                    COMMAND bash -c "basename ${OTOOL_OUTPUT}| sed -e 's/^[[:space:]]*//'"
                    OUTPUT_VARIABLE BASENAME
                )
                string(REPLACE "\n" "" BASENAME ${BASENAME})
                execute_process (
                    COMMAND bash -c "dirname ${OTOOL_OUTPUT}| sed -e 's/^[[:space:]]*//'"
                    OUTPUT_VARIABLE DIRNAME
                )
                string(REPLACE "\n" "" DIRNAME ${DIRNAME})
                if(NOT DIRNAME MATCHES "/usr/lib")
                    execute_process (
                        COMMAND bash -c "install_name_tool -change ${OTOOL_OUTPUT} ${CPACK_INSTALL_PREFIX}/${BASENAME} ${LIB_PATH}/${ITEM}"
                        OUTPUT_VARIABLE OUTPUT_INSTALL_NAME_TOOL
                    )
                endif()

            endforeach()
        endif()
    endforeach()
endfunction()
string(TOLOWER ${CPACK_COMPONENT_DEPENDENCIES_GROUP} CPACK_COMPONENT_DEPENDENCIES_GROUP )
set(LIB_PATH "${CPACK_TEMPORARY_DIRECTORY}/${CPACK_COMPONENT_DEPENDENCIES_GROUP}${CPACK_INSTALL_PREFIX}/lib")
change_rpath(${LIB_PATH} LIB)

set(LIB_PATH "${CPACK_TEMPORARY_DIRECTORY}/facemgr${CPACK_INSTALL_PREFIX}/lib")
change_rpath(${LIB_PATH} LIB)
set(LIB_PATH "${CPACK_TEMPORARY_DIRECTORY}/libhicntransport${CPACK_INSTALL_PREFIX}/lib")
change_rpath(${LIB_PATH} LIB)
set(LIB_PATH "${CPACK_TEMPORARY_DIRECTORY}/libhicn${CPACK_INSTALL_PREFIX}/lib")
change_rpath(${LIB_PATH} LIB)

set(EXE_PATH "${CPACK_TEMPORARY_DIRECTORY}/hicn-utils${CPACK_INSTALL_PREFIX}/bin")
change_rpath(${EXE_PATH} EXE)
set(EXE_PATH "${CPACK_TEMPORARY_DIRECTORY}/hicn-light${CPACK_INSTALL_PREFIX}/bin")
change_rpath(${EXE_PATH} EXE)
set(EXE_PATH "${CPACK_TEMPORARY_DIRECTORY}/hicn-apps${CPACK_INSTALL_PREFIX}/bin")
change_rpath(${EXE_PATH} EXE)
set(EXE_PATH "${CPACK_TEMPORARY_DIRECTORY}/facemgr${CPACK_INSTALL_PREFIX}/bin")
change_rpath(${EXE_PATH} EXE)
#set(EXE_PATH "${CPACK_TEMPORARY_DIRECTORY}/hicnctrl${CPACK_INSTALL_PREFIX}/bin")
#change_rpath(${EXE_PATH} EXE)
