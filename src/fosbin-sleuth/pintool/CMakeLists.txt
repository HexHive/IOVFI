add_subdirectory("shared-library-support")

set(PINTOOL_SOURCES
        ${PINTOOL_NAME}.cpp
        ${PINTOOL_NAME}.h
        PinLogger.cpp
        X86Context.cpp
        AllocatedArea.cpp
        FBZergContext.cpp
        ContextReader.cpp
        ZergCommandServer.cpp
        ZergCommandServer.h
        ZergCommand.h
        ZergCommand.cpp
        ZergMessage.cpp
        makefile.rules.in
        makefile.in
        )

add_custom_command(OUTPUT ${PROJECT_BINARY_DIR}/pintools
        COMMAND mkdir -p ${PROJECT_BINARY_DIR}/pintools/intel64
        )

add_custom_command(OUTPUT ${PROJECT_BINARY_DIR}/pintools/intel64/${PINTOOL_NAME}.so
        COMMAND make -B -f makefile TARGET=intel64 PIN_ROOT=${CMAKE_SOURCE_DIR}/src/pin/pin-${PIN_VERSION} OBJDIR=${PROJECT_BINARY_DIR}/pintools/intel64/
        DEPENDS ${PINTOOL_SOURCES}
        )

configure_file(makefile.rules.in makefile.rules)
configure_file(makefile.in makefile)

add_custom_target(${PINTOOL_NAME}
        DEPENDS ${PROJECT_BINARY_DIR}/pintools
        ${PROJECT_BINARY_DIR}/pintools/intel64/${PINTOOL_NAME}.so
        ${PINTOOL_SOURCES}
        )