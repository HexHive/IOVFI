add_executable( ${EXE_NAME} main.cpp )

target_link_libraries( ${EXE_NAME} stdc++fs )

TARGET_SOURCES( ${EXE_NAME}
        PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/../identifiers/functionIdentifier.cpp
        ${CMAKE_CURRENT_LIST_DIR}/../identifiers/identifierFactory.cpp
        ${CMAKE_CURRENT_LIST_DIR}/../identifiers/fbf-memcpy.cpp
        ${CMAKE_CURRENT_LIST_DIR}/../identifiers/fbf-strcpy.cpp
        ${CMAKE_CURRENT_LIST_DIR}/../identifiers/fbf-sprintf.cpp
        ${CMAKE_CURRENT_LIST_DIR}/../identifiers/fbf-strncpy.cpp
        ${CMAKE_CURRENT_LIST_DIR}/../identifiers/fbf-memmove.cpp
        ${CMAKE_CURRENT_LIST_DIR}/../identifiers/fbf-pow.cpp
        ${CMAKE_CURRENT_LIST_DIR}/coord/binSection.cpp
        ${CMAKE_CURRENT_LIST_DIR}/coord/fullTest.cpp
        ${CMAKE_CURRENT_LIST_DIR}/coord/testRun.cpp
        )