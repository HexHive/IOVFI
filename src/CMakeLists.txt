add_executable(${PROJECT_NAME} main.cpp)

add_subdirectory(identifiers)

install(TARGETS ${PROJECT_NAME} DESTINATION bin)
