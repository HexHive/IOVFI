add_custom_command(OUTPUT ${PROJECT_BINARY_DIR}/${PINTOOL_NAME}.so
        COMMAND make PIN_ROOT=../../../src/pin/pin-${PIN_VERSION} OBJDIR=${PROJECT_BINARY_DIR}/
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/fosbin-sleuth/pintool
        )

add_custom_target(${PINTOOL_NAME}
        DEPENDS ${PROJECT_BINARY_DIR}/${PINTOOL_NAME}.so
        )