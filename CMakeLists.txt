set(CMAKE_POLICY_DEFAULT_CMP0077 NEW)
cmake_minimum_required(VERSION 3.8 FATAL_ERROR)

project(mdnsServicepp VERSION 0.0.1)

set(CMAKE_CXX_STANDARD_REQUIRED YES)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS NO)
set(CMAKE_C_STANDARD 11)

option(MDNSSERVICE_BUILD_EXAMPLE "Build example" ON)

#add_subdirectory(${CMAKE_SOURCE_DIR}/include/mdns)
#target_include_directories(${PROJECT_NAME} ${CMAKE_SOURCE_DIR}/include/mdns)
add_library(${PROJECT_NAME} ${CMAKE_SOURCE_DIR}/mdnsService.cpp)

if(MDNSSERVICE_BUILD_EXAMPLE)
  add_executable(${PROJECT_NAME}_example example.cpp)
  target_link_libraries(${PROJECT_NAME}_example ${PROJECT_NAME})
endif()

