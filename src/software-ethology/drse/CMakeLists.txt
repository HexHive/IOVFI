set(TOOL_NAME drse)

set(DynamoRIO_DIR ${CMAKE_CURRENT_BINARY_DIR}/../../dynamorio/cmake)

find_package(DynamoRIO)
if (NOT DynamoRIO_FOUND)
    message(FATAL_ERROR "DynamoRIO package required to build")
endif (NOT DynamoRIO_FOUND)

set(DRSE_SOURCES
        empty.c
        )

add_library(${TOOL_NAME} SHARED ${DRSE_SOURCES})
add_dependencies(${TOOL_NAME} dynamorio)
configure_DynamoRIO_client(${TOOL_NAME})