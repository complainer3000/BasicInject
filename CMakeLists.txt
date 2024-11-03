cmake_minimum_required(VERSION 3.10)

project(BasicDLLInjector)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

file(GLOB_RECURSE SOURCES "src/*.cpp" "src/*.h")

add_executable(${PROJECT_NAME} ${SOURCES})