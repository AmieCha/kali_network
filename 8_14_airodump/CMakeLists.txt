cmake_minimum_required(VERSION 3.10)
project(airodump CXX)
set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH})

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

add_compile_options(-Wall -Wextra)

find_package(PCAP REQUIRED)
find_package(Threads REQUIRED)

add_executable(airodump airodump.cpp)
target_link_libraries(airodump PRIVATE ${PCAP_LIBRARIES} Threads::Threads)
target_include_directories(airodump PRIVATE ${PCAP_INCLUDE_DIR})