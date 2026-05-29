cmake_minimum_required(VERSION 3.14)

project(EdgeAccessPKI VERSION 1.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(EDGEACCESSPKI_TINY_PKI_PATH "" CACHE PATH
    "Use a local TinyPKI checkout instead of fetching the release tag")

if (EDGEACCESSPKI_TINY_PKI_PATH)
    add_subdirectory("${EDGEACCESSPKI_TINY_PKI_PATH}" tinypki-local)
else ()
    include(FetchContent)
    FetchContent_Declare(
        TinyPKI
        GIT_REPOSITORY https://github.com/kakahuote1/TinyPKI.git
        GIT_TAG v1.0.0
    )
    FetchContent_MakeAvailable(TinyPKI)
endif ()

add_executable(edge_access_pki src/main.c)
target_link_libraries(edge_access_pki PRIVATE tinypki)

if (MSVC)
    target_compile_options(edge_access_pki PRIVATE /W4)
else ()
    target_compile_options(edge_access_pki PRIVATE -Wall -Wextra)
endif ()

install(TARGETS edge_access_pki RUNTIME DESTINATION bin)
install(DIRECTORY config/ DESTINATION etc/edgeaccesspki)
