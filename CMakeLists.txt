cmake_minimum_required(VERSION 3.10.2)
project(fosbin-flop)

set(${PROJECT_NAME}-VERSION-MAJOR 0)
set(${PROJECT_NAME}-VERSION-MINOR 1)
set(CMAKE_CXX_STANDARD 14)

configure_file("inc/${PROJECT_NAME}-config.h.in"
        "inc/${PROJECT_NAME}-config.h")

include_directories(inc ${CMAKE_CURRENT_BINARY_DIR}/inc)

add_subdirectory(src)