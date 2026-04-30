cmake_minimum_required(VERSION 3.20)

project(opendkim-ng
    VERSION 2.10.3
    DESCRIPTION "OpenDKIM DKIM library and milter daemon"
    LANGUAGES C
)

add_compile_definitions(_GNU_SOURCE)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_subdirectory(libopendkim)
