add_executable(heapexplorer WIN32
    main.cpp
    app.cpp
    pipe_server.cpp
    injector.cpp
)
target_include_directories(heapexplorer PRIVATE ${CMAKE_SOURCE_DIR})
target_link_libraries(heapexplorer PRIVATE imgui_lib d3d11 dxgi comdlg32)
set_target_properties(heapexplorer PROPERTIES
    OUTPUT_NAME "HeapExplorer"
)
