cmake_minimum_required(VERSION 3.15)
project(ziovpontvrs LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---- GUI application (tray icon, main window) ----
add_executable(${PROJECT_NAME} WIN32 src/main.cpp)
target_link_libraries(${PROJECT_NAME} PRIVATE shell32 advapi32)

# ---- Windows service ----
add_executable(${PROJECT_NAME}_svc src/service.cpp)
target_link_libraries(${PROJECT_NAME}_svc PRIVATE advapi32 wtsapi32 userenv)

# MinGW requires -municode for wide‑char entry points
if(MINGW)
    target_compile_options(${PROJECT_NAME} PRIVATE -municode)
    target_link_options(${PROJECT_NAME} PRIVATE -municode)

    target_compile_options(${PROJECT_NAME}_svc PRIVATE -municode)
    target_link_options(${PROJECT_NAME}_svc PRIVATE -municode)
endif()
