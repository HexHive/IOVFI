add_executable( ${FUNC_CLASSIFIER}
        main.cpp
        )

target_include_directories( ${FUNC_CLASSIFIER} PRIVATE
        ../../inc/${FUNC_CLASSIFIER}
        .
        )

target_link_libraries( ${FUNC_CLASSIFIER} stdc++fs )

target_sources( ${FUNC_CLASSIFIER}
    PUBLIC
        ../common/binaryDescriptor.cpp
        ../common/binSection.cpp
        ../common/fullTest.cpp
        ../common/testRun.cpp
        ../common/iTestCase.cpp
        coord/fullSleuthTest.cpp
        TestCases.inc
        )
