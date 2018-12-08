add_library(${MAIN_HOOK} SHARED
        main_hook.c
        )

target_link_libraries(
        ${MAIN_HOOK}
        dl
)

set_target_properties(${MAIN_HOOK} PROPERTIES
        VERSION "${PROJECT_VERSION}"
        SOVERSION 1
        )