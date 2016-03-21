FILE(GLOB SOURCES "*.cpp")

INCLUDE_DIRECTORIES(
    ${PROJECT_SOURCE_DIR}/include/
    ${PCAP_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

# Find pthread library
FIND_PACKAGE(Threads REQUIRED)

# Link against GoogleTest, libtins and pthread.
LINK_LIBRARIES(
    tins 
    ${CMAKE_THREAD_LIBS_INIT}
    ${PCAP_LIBRARY}
)

ADD_EXECUTABLE(active_tester EXCLUDE_FROM_ALL ${SOURCES})
