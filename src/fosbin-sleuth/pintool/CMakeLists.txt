add_custom_command(OUTPUT obj-intel64/${PINTOOL_NAME}.so
        COMMAND make PIN_ROOT=../../../src/pin/pin-${PIN_VERSION} ${PINTOOL_NAME}
        SOURCES ${PINTOOL_NAME}.cpp
        )