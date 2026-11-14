add_executable(launcher main.cpp)
target_include_directories(launcher PRIVATE ${CMAKE_SOURCE_DIR})
set_target_properties(launcher PROPERTIES
    OUTPUT_NAME "launcher"
)
