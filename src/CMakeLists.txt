add_subdirectory(software-ethology)

set(VALGRIND_TOOL_NAME segrind)
set(VALGRIND_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/valgrind/install)
set(VALGRIND_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/valgrind/${VALGRIND_TOOL_NAME})

set(VALGRIND_TOOL_SRCS
        ${VALGRIND_SRC_DIR}/clo.c
        ${VALGRIND_SRC_DIR}/se_main.c
        )

set(VALGRIND_TOOL_INCS
        ${VALGRIND_SRC_DIR}/se.h
        )

add_custom_target(MakeValgrindDir
        COMMAND mkdir -p ${CMAKE_CURRENT_BINARY_DIR}/valgrind
        BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/valgrind
        )

add_custom_target(ConfigureValgrind
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/valgrind
        BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/valgrind/Makefile
        DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/valgrind ${VALGRIND_SRC_DIR}/Makefile.am
        COMMAND cd ${CMAKE_CURRENT_SOURCE_DIR}/valgrind/ && bash ${CMAKE_CURRENT_SOURCE_DIR}/valgrind/autogen.sh
        COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/valgrind/configure --prefix=${VALGRIND_INSTALL_DIR} --srcdir ${CMAKE_CURRENT_SOURCE_DIR}/valgrind
        )

add_custom_target(BuildValgrind
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/valgrind
        DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/valgrind ${VALGRIND_TOOL_SRCS} ${VALGRIND_TOOL_INCS}
        BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/valgrind/${VALGRIND_TOOL_NAME}/${VALGRIND_TOOL_NAME}-amd64-linux
        COMMAND make
        )

add_custom_target(InstallValgrind
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/valgrind
        BYPRODUCTS ${VALGRIND_INSTALL_DIR}/bin/valgrind
        COMMAND make install
        )

#add_dependencies(InstallValgrind BuildValgrind ConfigureValgrind)
#add_dependencies(BuildValgrind ConfigureValgrind)
#add_dependencies(ConfigureValgrind MakeValgrindDir)
