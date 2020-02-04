set(PROJ_NAME fosbin)
set(FUNC_CLASSIFIER ${PROJ_NAME}-sleuth)
set(PIN_VERSION 3.11)
set(PINTOOL_NAME ${PROJ_NAME}-zergling)

cmake_minimum_required(VERSION 3.5.1)

project(${PROJ_NAME})

set(${PROJECT_NAME}-VERSION-MAJOR 1)
set(${PROJECT_NAME}-VERSION-MINOR 0)
set(CMAKE_CXX_STANDARD 17)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

set(CMAKE_VERBOSE_MAKEFILE True)

include_directories(inc ${CMAKE_CURRENT_BINARY_DIR}/inc src/pin/pin-${PIN_VERSION}/source/include)

add_subdirectory(src)
