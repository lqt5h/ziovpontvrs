cmake_minimum_required(VERSION 3.15)
project(ziovpontvrs LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---- widl: generate RPC stubs from the IDL ----
find_program(WIDL_EXECUTABLE
    NAMES x86_64-w64-mingw32-widl widl
)
if(NOT WIDL_EXECUTABLE)
    message(FATAL_ERROR
        "widl not found. Install the mingw-w64 tools package "
        "(provides x86_64-w64-mingw32-widl).")
endif()

set(RPC_IDL     ${CMAKE_CURRENT_SOURCE_DIR}/src/rpc_iface.idl)
set(RPC_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/rpc_gen)
set(RPC_HDR     ${RPC_GEN_DIR}/rpc_iface.h)
set(RPC_CLIENT  ${RPC_GEN_DIR}/rpc_iface_c.c)
set(RPC_SERVER  ${RPC_GEN_DIR}/rpc_iface_s.c)

file(MAKE_DIRECTORY ${RPC_GEN_DIR})

add_custom_command(
    OUTPUT  ${RPC_HDR} ${RPC_CLIENT} ${RPC_SERVER}
    COMMAND ${WIDL_EXECUTABLE}
            -h -H ${RPC_HDR}
            -c -C ${RPC_CLIENT}
            -s -S ${RPC_SERVER}
            ${RPC_IDL}
    DEPENDS ${RPC_IDL}
    COMMENT "widl: generating RPC stubs from rpc_iface.idl"
    VERBATIM
)

# ---- GUI application (tray icon, main window, RPC client) ----
add_executable(${PROJECT_NAME} WIN32
    src/main.cpp
    ${RPC_CLIENT}
    ${RPC_HDR}
)
target_include_directories(${PROJECT_NAME} PRIVATE ${RPC_GEN_DIR} src)
target_link_libraries(${PROJECT_NAME} PRIVATE shell32 advapi32 rpcrt4)

# ---- Windows service (session launcher, RPC server) ----
add_executable(${PROJECT_NAME}_svc
    src/service.cpp
    ${RPC_SERVER}
    ${RPC_HDR}
)
target_include_directories(${PROJECT_NAME}_svc PRIVATE ${RPC_GEN_DIR} src)
target_link_libraries(${PROJECT_NAME}_svc PRIVATE advapi32 wtsapi32 userenv rpcrt4)

# MinGW requires -municode for wide-char entry points
if(MINGW)
    target_compile_options(${PROJECT_NAME} PRIVATE -municode)
    target_link_options(${PROJECT_NAME} PRIVATE -municode)

    target_compile_options(${PROJECT_NAME}_svc PRIVATE -municode)
    target_link_options(${PROJECT_NAME}_svc PRIVATE -municode)
endif()
