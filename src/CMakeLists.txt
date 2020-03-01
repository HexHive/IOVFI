add_subdirectory(software-ethology)

add_custom_target(MakeValgrindDir
        COMMAND mkdir -p ${CMAKE_CURRENT_BINARY_DIR}/valgrind
        )

add_custom_target(ConfigureValgrind
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/valgrind
        BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/valgrind/Makefile
        COMMAND cd ${CMAKE_CURRENT_SOURCE_DIR}/valgrind/ && bash ${CMAKE_CURRENT_SOURCE_DIR}/valgrind/autogen.sh
        COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/valgrind/configure --prefix=${CMAKE_CURRENT_BINARY_DIR}/valgrind --srcdir ${CMAKE_CURRENT_SOURCE_DIR}/valgrind
        )

add_custom_target(BuildValgrind
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/valgrind
        COMMAND make
        )

add_custom_target(InstallValgrind
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/valgrind
        BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/valgrind/bin/valgrind
        COMMAND make install
        )

add_dependencies(InstallValgrind BuildValgrind ConfigureValgrind)
add_dependencies(BuildValgrind ConfigureValgrind)
add_dependencies(ConfigureValgrind MakeValgrindDir)
