add_library(worker SHARED
    dllmain.cpp
    hooks.cpp
    snapshot.cpp
    pipe_client.cpp
)
target_include_directories(worker PRIVATE ${CMAKE_SOURCE_DIR})
target_link_libraries(worker PRIVATE minhook)
set_target_properties(worker PROPERTIES
    OUTPUT_NAME "worker"
)
