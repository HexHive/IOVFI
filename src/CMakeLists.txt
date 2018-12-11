file(GLOB COMMON_SRC
        common/*.cpp
        )

add_subdirectory(capstone)
add_subdirectory(fosbin-flop)
add_subdirectory(fosbin-sleuth)
add_subdirectory(llvm)
