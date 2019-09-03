add_library(googletest STATIC gmock-gtest-all.cc)
target_include_directories(googletest PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(googletest Threads::Threads)
