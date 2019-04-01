set( CMAKE_C_COMPILER clang )
set( CMAKE_CXX_COMPILER clang++ )
set( LLVM_PARALLEL_LINK_JOBS "2" )

set( PROJ_NAME fosbin )
set( FUNC_CLASSIFIER ${PROJ_NAME}-sleuth )
set( PIN_VERSION 3.7 )
set( PINTOOL_NAME ${PROJ_NAME}-zergling )

cmake_minimum_required( VERSION 3.10.2 )

project( ${PROJ_NAME} )

set ( CMAKE_BUILD_TYPE Debug )

set( ${PROJECT_NAME}-VERSION-MAJOR 0 )
set( ${PROJECT_NAME}-VERSION-MINOR 3 )
set( CMAKE_CXX_STANDARD 17 )

set( CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin )
set( CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib )

set( CMAKE_VERBOSE_MAKEFILE True )

set(THREADS_PREFER_PTHREAD_FLAG ON)

include_directories( inc ${CMAKE_CURRENT_BINARY_DIR}/inc src/pin/pin-${PIN_VERSION}/source/include )

add_subdirectory( src )
