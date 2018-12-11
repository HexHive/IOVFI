add_library(${MAIN_HOOK} SHARED
        main_hook.c
        proc_maps_parser/pmparser.c
        )

target_include_directories(
        ${MAIN_HOOK} PRIVATE
        proc_maps_parser
)

target_link_libraries(
        ${MAIN_HOOK}
        dl
)

set_target_properties(${MAIN_HOOK} PROPERTIES
        VERSION "${PROJECT_VERSION}"
        SOVERSION 1
        )