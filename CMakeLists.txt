# SPDX-FileCopyrightText: (C) 2025 Siemens
# SPDX-License-Identifier: MIT
# 
# Authors:
#   Eugen Kremer <eugen.kremer@siemens.com>
#

cmake_minimum_required(VERSION 3.10)
project(pkcs11-to-cmd C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(COVERAGE "Build with coverage" ON)

find_package(OpenSSL REQUIRED COMPONENTS Crypto)
find_package(PkgConfig REQUIRED)
pkg_check_modules(P11Kit REQUIRED p11-kit-1)

if(COVERAGE)
    message(STATUS "Compiling test targets with coverage enabled")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --coverage -fprofile-update=atomic")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --coverage -fprofile-update=atomic")
endif()

file(GLOB_RECURSE SRC_FILES src/*.cpp)

add_library(pkcs11-to-cmd SHARED ${SRC_FILES})

target_link_libraries(pkcs11-to-cmd PRIVATE OpenSSL::Crypto pthread)
target_include_directories(pkcs11-to-cmd PRIVATE ${P11Kit_INCLUDE_DIRS})
