cmake_minimum_required(VERSION 3.10)
project(Project_iLy CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)

add_executable(ily
    src/main.cpp
    src/parser.cpp
    src/timeline.cpp
    src/attribution.cpp
    src/presentation.cpp
)
