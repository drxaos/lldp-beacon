set (CMAKE_CXX_STANDARD 11)
add_definitions(-DWPCAP -DHAVE_REMOTE)
cmake_minimum_required(VERSION 3.5)

project(lldp_beacon)

include_directories(${CMAKE_SOURCE_DIR}/WpdPack/Include)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -U__STRICT_ANSI__")
set(CMAKE_EXE_LINKER_FLAGS "-static-libgcc -static-libstdc++ -static")

set(SOURCE_FILES main.cpp wmic.cpp dbg.cpp)
add_executable(lldp_beacon ${SOURCE_FILES})

find_library(WPCAPLIB wpcap)
find_library(PACKETLIB packet)
find_library(IPHLPAPILIB iphlpapi)
target_link_libraries(lldp_beacon ${WPCAPLIB} ${PACKETLIB} ${IPHLPAPILIB})
