add_executable(dump-rules-ast main.cpp)
target_link_libraries(dump-rules-ast yaramod)

if(YARAMOD_ASAN)
    target_compile_options(dump-rules-ast PRIVATE "-fsanitize=address" "-fno-omit-frame-pointer")
    target_link_options(dump-rules-ast PRIVATE "-fsanitize=address")
endif()
