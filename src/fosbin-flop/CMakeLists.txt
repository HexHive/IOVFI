add_executable( ${IDENTIFIER_NAME} main.cpp )

target_include_directories( ${IDENTIFIER_NAME} PRIVATE
        ../../inc/${IDENTIFIER_NAME}
        )

target_link_libraries( ${IDENTIFIER_NAME}
        stdc++fs
        pthread
        dl
        ${Boost_LIBRARIES}
        )

TARGET_SOURCES( ${IDENTIFIER_NAME}
        PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/coord/fullIdentifierTest.cpp
        ${CMAKE_CURRENT_LIST_DIR}/../common/binaryDescriptor.cpp
        ${COMMON_SRC}
        identifiers/identifierNodeTestCase.cpp
        identifiers/functionIdentifierNodeI.cpp
        )
