cmake_minimum_required(VERSION 3.10)
project(shared_info)

include(CheckIPOSupported)

set(CMAKE_CXX_STANDARD 20)

set(FORT_ENABLE_TESTING OFF CACHE INTERNAL "")

add_subdirectory(third-party/libfort)

include_directories(include)

file(GLOB_RECURSE include_files
  include/*.h
)

add_executable(shared_info
   src/main.cpp
)

# target_link_libraries(
#   verilog_sim PRIVATE  ${Boost_Libraries}
# )
target_link_libraries(shared_info PRIVATE fort)


check_ipo_supported(RESULT supported OUTPUT error)

if(supported)
  message(STATUS "LTO supported")
  set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
else()
  message(STATUS "LTO not supported")
endif()

# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -s")
# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -s")
