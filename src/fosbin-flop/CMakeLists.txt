add_executable( ${IDENTIFIER_NAME} main.cpp )

target_include_directories( ${IDENTIFIER_NAME} PRIVATE
        ../../inc/${IDENTIFIER_NAME}
        )

target_link_libraries( ${IDENTIFIER_NAME}
        stdc++fs pthread
        )

TARGET_SOURCES( ${IDENTIFIER_NAME}
        PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/identifiers/functionIdentifier.cpp
        ${CMAKE_CURRENT_LIST_DIR}/identifiers/identifierFactory.cpp
        ${CMAKE_CURRENT_LIST_DIR}/identifiers/fbf-memcpy.cpp
        ${CMAKE_CURRENT_LIST_DIR}/identifiers/fbf-strcpy.cpp
        ${CMAKE_CURRENT_LIST_DIR}/identifiers/fbf-sprintf.cpp
        ${CMAKE_CURRENT_LIST_DIR}/identifiers/fbf-strncpy.cpp
        ${CMAKE_CURRENT_LIST_DIR}/identifiers/fbf-memmove.cpp
        ../common/binSection.cpp
        ${CMAKE_CURRENT_LIST_DIR}/coord/fullIdentifierTest.cpp
        ../common/fullTest.cpp
        ../common/testRun.cpp
        ../common/iTestCase.cpp
        ${CMAKE_CURRENT_LIST_DIR}/../common/binaryDescriptor.cpp
        )
