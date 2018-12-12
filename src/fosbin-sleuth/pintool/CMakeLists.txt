set(PINTOOL_SOURCES
        ${PINTOOL_NAME}.cpp
        makefile.rules.in
        makefile.in
        )

add_custom_command(OUTPUT ${PROJECT_BINARY_DIR}/${PINTOOL_NAME}.so
        COMMAND make -f makefile TARGET=intel64 PIN_ROOT=${CMAKE_SOURCE_DIR}/src/pin/pin-${PIN_VERSION} OBJDIR=${PROJECT_BINARY_DIR}/
        DEPENDS ${PINTOOL_SOURCES}
        )

configure_file(makefile.rules.in makefile.rules)
configure_file(makefile.in makefile)

add_custom_target(${PINTOOL_NAME}
        DEPENDS ${PROJECT_BINARY_DIR}/${PINTOOL_NAME}.so ${PINTOOL_SOURCES}
        )