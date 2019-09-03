add_subdirectory(googletest)

set(TEST_FILES
	pog_tests.cpp
	test_automaton.cpp
	test_grammar.cpp
	test_item.cpp
	test_parser.cpp
	test_parsing_table.cpp
	test_precedence.cpp
	test_rule.cpp
	test_rule_builder.cpp
	test_state.cpp
	test_symbol.cpp
	test_token.cpp
	test_tokenizer.cpp
	test_token_builder.cpp
	test_utils.cpp
)

add_executable(pog_tests ${TEST_FILES})
if (MSVC)
	# This flag is needed for MSVC because test_parser.cpp exceeds limit of number of section in Debug x64 build
	set_source_files_properties(test_parser.cpp PROPERTIES COMPILE_FLAGS /bigobj)
endif()
target_link_libraries(pog_tests pog googletest)
