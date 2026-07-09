cmake_minimum_required(VERSION 3.15)

project(MTBE)

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(RELIC REQUIRED)

include_directories(
    include
    ${RELIC_INCLUDE_DIRS}
)

add_executable(mtbe

    main.cpp

    setup.cpp

    keygen.cpp

    encrypt.cpp

    decrypt.cpp

    recover.cpp

    polynomial.cpp

    hash.cpp

    utils.cpp
)

target_link_libraries(
    mtbe
    ${RELIC_LIBRARIES}
)