add_executable(${PROJECT_NAME} main.cpp)
target_link_libraries(${PROJECT_NAME} stdc++fs)

add_subdirectory(identifiers)
add_subdirectory(coord)

install(TARGETS ${PROJECT_NAME}
        RUNTIME DESTINATION bin/
        )
