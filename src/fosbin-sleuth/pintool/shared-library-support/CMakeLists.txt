add_executable(fb-load
        load-shared.c
        )

target_link_libraries("fb-load"
        dl
        )