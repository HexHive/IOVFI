add_executable( ${FUNC_CLASSIFIER}
        main.cpp
        )

add_dependencies( ${FUNC_CLASSIFIER}
        capstone-shared
        )

target_include_directories( ${FUNC_CLASSIFIER} PRIVATE
        ../../inc/${FUNC_CLASSIFIER}
        .
        ${Boost_INCLUDE_DIRS}
        ../capstone/include
        )

target_link_libraries( ${FUNC_CLASSIFIER}
        stdc++fs
        pthread
        ${Boost_LIBRARIES}
        dl
        )

target_link_libraries( ${FUNC_CLASSIFIER} "-L${CMAKE_BINARY_DIR}/lib" capstone )

target_sources( ${FUNC_CLASSIFIER}
    PUBLIC
        ../common/binaryDescriptor.cpp
        ../common/binSection.cpp
        ../common/fullTest.cpp
        ../common/testRun.cpp
        ../common/iTestCase.cpp
        coord/fullSleuthTest.cpp
        protectedBuffer.cpp
        TestCases.inc
        argumentCountTestCase.cpp
        )
