cmake_minimum_required(VERSION 3.16)
project(airodump)

set(CMAKE_CXX_STANDARD 17)

add_executable(airodump main.cpp)
target_link_libraries(airodump pcap)