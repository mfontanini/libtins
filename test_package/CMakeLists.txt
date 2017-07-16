cmake_minimum_required(VERSION 3.1.3)
project(libtins-test CXX)

include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
conan_basic_setup()

file(GLOB SOURCE_FILES "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")

add_executable(${CMAKE_PROJECT_NAME} ${SOURCE_FILES})
target_link_libraries(${CMAKE_PROJECT_NAME} ${CONAN_LIBS})
set_property(TARGET ${CMAKE_PROJECT_NAME} PROPERTY CXX_STANDARD 11)

enable_testing()
add_test(NAME test-libtins-package
         WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/bin
         COMMAND ${CMAKE_PROJECT_NAME})
