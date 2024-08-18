cmake_minimum_required(VERSION 3.29)
project(qnetworkc__)

set(CMAKE_CXX_STANDARD 20)

add_executable(qnetworkc__ main.cpp)

target_link_libraries(${PROJECT_NAME} ws2_32 iphlpapi)