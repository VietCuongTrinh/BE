cmake_minimum_required(VERSION 3.16)

project(BroadcastEncryption)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

###############################################################
# Compiler
###############################################################

if(MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra -O3)
endif()

###############################################################
# OpenSSL
###############################################################

find_package(OpenSSL REQUIRED)

###############################################################
# Include
###############################################################

include_directories(
    include
)

###############################################################
# Source Files
###############################################################

set(SOURCES

    src/main.cpp

    src/setup.cpp
    src/keygen.cpp
    src/encrypt.cpp
    src/partial_decrypt.cpp
    src/collaborative_decrypt.cpp

    src/ecc.cpp
    src/util.cpp
    src/lss.cpp
)

###############################################################
# Executable
###############################################################

add_executable(
    BroadcastEncryption
    ${SOURCES}
)

###############################################################
# Link
###############################################################

target_link_libraries(
    BroadcastEncryption

    OpenSSL::SSL
    OpenSSL::Crypto
)

###############################################################
# Output
###############################################################

set_target_properties(
    BroadcastEncryption
    PROPERTIES

    RUNTIME_OUTPUT_DIRECTORY
    ${PROJECT_SOURCE_DIR}/bin
)