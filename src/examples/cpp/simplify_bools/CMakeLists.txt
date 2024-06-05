add_executable(simplify-bools main.cpp)
target_link_libraries(simplify-bools yaramod)

if(YARAMOD_ASAN)
    target_compile_options(simplify-bools PRIVATE "-fsanitize=address" "-fno-omit-frame-pointer")
    target_link_options(simplify-bools PRIVATE "-fsanitize=address")
endif()
