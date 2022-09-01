set(CMAKE_POLICY_DEFAULT_CMP0077 NEW)
cmake_minimum_required(VERSION 3.8 FATAL_ERROR)

project(mdnsServicepp VERSION 0.0.1)

set(CMAKE_CXX_STANDARD_REQUIRED YES)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_EXTENSIONS NO)
set(CMAKE_C_STANDARD 11)

option(MDNSSERVICE_BUILD_EXAMPLE "Build example" OFF)
option(UNDEFINED_SANITIZER "Enable Clang UndefinedBehaviorSanitizer" OFF)
option(ADDRESS_SANITIZER "Enable Clang AddressSanitizer" OFF)

set(CMAKE_THREAD_LIBS_INIT "-lpthread")
set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads REQUIRED)

if (ADDRESS_SANITIZER AND ${CMAKE_CXX_COMPILER_ID} STREQUAL "Clang")
    message("!! AddressSanitizer enabled for debug build")
    set(CMAKE_CXX_FLAGS_DEBUG
            "${CMAKE_CXX_FLAGS_DEBUG} -O1 -fno-omit-frame-pointer -fsanitize=address")
endif ()

if (UNDEFINED_SANITIZER AND ${CMAKE_CXX_COMPILER_ID} STREQUAL "Clang")
    message("!! UndefinedBehaviorSanitizer enabled for debug build")
    set(CMAKE_CXX_FLAGS_DEBUG
            "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=undefined")
endif ()

if (MDNSSERVICE_BUILD_EXAMPLE)
    add_executable(${PROJECT_NAME}_example example.cpp)
    target_include_directories(${PROJECT_NAME}_example INTERFACE ${CMAKE_SOURCE_DIR})
    target_compile_options(${PROJECT_NAME}_example PUBLIC -Wall -Wextra -pedantic)
    target_link_libraries(${PROJECT_NAME}_example PRIVATE Threads::Threads)
endif ()



