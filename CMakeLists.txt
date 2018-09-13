set( CMAKE_C_COMPILER clang )
set( CMAKE_CXX_COMPILER clang++ )
set( LLVM_PARALLEL_LINK_JOBS "2" )

set( PROJ_NAME fosbin )
set( LIBRARY_NAME ${PROJ_NAME}-scribe )
set( IDENTIFIER_NAME ${PROJ_NAME}-flop )
set( FUNC_CLASSIFIER ${PROJ_NAME}-sleuth )

cmake_minimum_required( VERSION 3.10.2 )

project( ${PROJ_NAME} )

set (CMAKE_BUILD_TYPE Debug)
set ( LLVM_TARGETS_TO_BUILD "X86" )

set( ${PROJECT_NAME}-VERSION-MAJOR 0 )
set( ${PROJECT_NAME}-VERSION-MINOR 3 )
set( CMAKE_CXX_STANDARD 14 )

set( CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin )
set( CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib )

set( CMAKE_VERBOSE_MAKEFILE True )

configure_file( "inc/${PROJ_NAME}-config.h.in"
    "inc/${PROJ_NAME}-config.h")

configure_file( "inc/${IDENTIFIER_NAME}-config.h.in"
    "inc/${IDENTIFIER_NAME}-config.h")

configure_file( "inc/${FUNC_CLASSIFIER}-config.h.in"
    "inc/${FUNC_CLASSIFIER}-config.h")

include_directories( inc ${CMAKE_CURRENT_BINARY_DIR}/inc )

add_subdirectory( src )
