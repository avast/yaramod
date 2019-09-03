#include <gmock/gmock.h>

#include <pog/parser.h>

using namespace pog;
using namespace ::testing;

class TestParser : public ::testing::Test {};

TEST_F(TestParser,
RepeatingAs) {
	Parser<int> p;

	p.token("a").symbol("a");

	p.set_start_symbol("A");
	p.rule("A")
		.production("A", "a", [](auto&& args) {
			return 1 + args[0];
		})
		.production("a", [](auto&&) {
			return 1;
		});
	EXPECT_TRUE(p.prepare());

	std::stringstream input1("a");
	auto result = p.parse(input1);
	EXPECT_TRUE(result);
	EXPECT_EQ(result.value(), 1);

	std::stringstream input2("aaaa");
	result = p.parse(input2);
	EXPECT_TRUE(result);
	EXPECT_EQ(result.value(), 4);

	try
	{
		std::stringstream input3("aa aaa");
		p.parse(input3);
		FAIL() << "Expected syntax error";
	}
	catch (const SyntaxError& e)
	{
		EXPECT_STREQ(e.what(), "Syntax error: Unknown symbol on input, expected one of @end, a");
	}
}

TEST_F(TestParser,
RepeatingAsWithIgnoringWhitespaces) {
	Parser<int> p;

	p.token(R"(\s+)");
	p.token("a").symbol("a");

	p.set_start_symbol("A");
	p.rule("A")
		.production("A", "a", [](auto&& args) {
			return 1 + args[0];
		})
		.production("a", [](auto&&) {
			return 1;
		});
	EXPECT_TRUE(p.prepare());

	std::stringstream input1("a");
	auto result = p.parse(input1);
	EXPECT_TRUE(result);
	EXPECT_EQ(result.value(), 1);

	std::stringstream input2("aaaa");
	result = p.parse(input2);
	EXPECT_TRUE(result);
	EXPECT_EQ(result.value(), 4);

	std::stringstream input3("aa aaa");
	result = p.parse(input3);
	EXPECT_TRUE(result);
	EXPECT_EQ(result.value(), 5);
}

TEST_F(TestParser,
SameNumberOfAsAndBs) {
	Parser<int> p;

	p.token("a").symbol("a");
	p.token("b").symbol("b");

	p.set_start_symbol("S");
	p.rule("S")
		.production("a", "S", "b", [](auto&& args) {
			return 1 + args[1];
		})
		.production("a", "b", [](auto&&) {
			return 1;
		});
	EXPECT_TRUE(p.prepare());

	std::stringstream input1("ab");
	auto result = p.parse(input1);
	EXPECT_TRUE(result);
	EXPECT_EQ(result.value(), 1);

	std::stringstream input2("aaabbb");
	result = p.parse(input2);
	EXPECT_TRUE(result);
	EXPECT_EQ(result.value(), 3);

	try
	{
		std::stringstream input3("aabbb");
		p.parse(input3);
		FAIL() << "Expected syntax error";
	}
	catch (const SyntaxError& e)
	{
		EXPECT_STREQ(e.what(), "Syntax error: Unexpected b, expected one of @end");
	}

	try
	{
		std::stringstream input4("aaabb");
		p.parse(input4);
		FAIL() << "Expected syntax error";
	}
	catch (const SyntaxError& e)
	{
		EXPECT_STREQ(e.what(), "Syntax error: Unexpected @end, expected one of b");
	}
}

TEST_F(TestParser,
LalrButNotLrNorNqlalr) {
	Parser<int> p;

	p.token("a").symbol("a");
	p.token("b").symbol("b");
	p.token("c").symbol("c");
	p.token("d").symbol("d");
	p.token("g").symbol("g");

	p.set_start_symbol("S");
	p.rule("S")
		.production("a", "g", "d")
		.production("a", "A", "c")
		.production("b", "A", "d")
		.production("b", "g", "c");
	p.rule("A")
		.production("B");
	p.rule("B")
		.production("g");
	EXPECT_TRUE(p.prepare());

	std::stringstream input("agc");
	auto result = p.parse(input);
	EXPECT_TRUE(result);
}

TEST_F(TestParser,
Precedence) {
	Parser<int> p;

	p.token(R"(\s+)");
	p.token(R"(\+)").symbol("+").precedence(0, Associativity::Left);
	p.token(R"(-)").symbol("-").precedence(0, Associativity::Left);
	p.token(R"(\*)").symbol("*").precedence(1, Associativity::Left);
	p.token("[0-9]+").symbol("int").action([](std::string_view str) {
		return std::stoi(std::string{str});
	});

	p.set_start_symbol("E");
	p.rule("E")
		.production("E", "+", "E", [](auto&& args) {
			return args[0] + args[2];
		})
		.production("E", "-", "E", [](auto&& args) {
			return args[0] - args[2];
		})
		.production("E", "*", "E", [](auto&& args) {
			return args[0] * args[2];
		})
		.production("-", "E", [](auto&& args) {
			return -args[1];
		}).precedence(2, Associativity::Right)
		.production("int", [](auto&& args) {
			return args[0];
		});
	EXPECT_TRUE(p.prepare());

	std::stringstream input1("2 + 3 * 4 + 5");
	auto result = p.parse(input1);
	EXPECT_TRUE(result);
	EXPECT_EQ(result.value(), 19);

	std::stringstream input2("-5 - 3 - -10");
	result = p.parse(input2);
	EXPECT_TRUE(result);
	EXPECT_EQ(result.value(), 2);

	std::stringstream input3("5 + -3 * 10");
	result = p.parse(input3);
	EXPECT_TRUE(result);
	EXPECT_EQ(result.value(), -25);
}

TEST_F(TestParser,
Conflicts1) {
	Parser<int> p;

	p.token("a").symbol("a");

	p.set_start_symbol("sequence");
	p.rule("sequence")
		.production("sequence", "a")
		.production("maybea")
		.production();
	p.rule("maybea")
		.production("a")
		.production();

	auto report = p.prepare();
	EXPECT_FALSE(report);
	EXPECT_EQ(report.number_of_issues(), 3u);
	EXPECT_EQ(report.to_string(),
		"Shift-reduce conflict of symbol 'a' and rule 'sequence -> <eps>' in state 0\n"
		"Reduce-reduce conflict of rule 'sequence -> <eps>' and rule 'maybea -> <eps>' in state 0\n"
		"Shift-reduce conflict of symbol 'a' and rule 'maybea -> <eps>' in state 0"
	);
}

TEST_F(TestParser,
Conflicts2) {
	Parser<int> p;

	p.token("b").symbol("b");
	p.token("c").symbol("c");

	p.set_start_symbol("Y");
	p.rule("Y")
		.production("c", "c", "Z", "b");
	p.rule("Z")
		.production("c", "Z", "b")
		.production("c", "Z")
		.production();

	auto report = p.prepare();
	EXPECT_FALSE(report);
	EXPECT_EQ(report.number_of_issues(), 1u);
	EXPECT_EQ(report.to_string(), "Shift-reduce conflict of symbol 'b' and rule 'Z -> c Z' in state 6");
}

TEST_F(TestParser,
Conflicts3) {
	Parser<std::vector<std::string>> p;

	p.token("\\(").symbol("(");
	p.token("\\)").symbol(")");
	p.token("a").symbol("a");

	p.set_start_symbol("E");
	p.rule("E")
		.production("(", "E", ")", [](auto&& args) {
			args[1].push_back("E -> ( E )");
			return std::move(args[1]);
		})
		.production("PE", [](auto&& args) {
			args[0].push_back("E -> PE");
			return std::move(args[0]);
		});
	p.rule("PE")
		.production("(", "PE", ")", [](auto&& args) {
			args[1].push_back("PE -> ( PE )");
			return std::move(args[1]);
		})
		.production("a", [](auto&&) {
			return std::vector<std::string>{"PE -> a"};
		});

	auto report = p.prepare();
	EXPECT_FALSE(report);
	EXPECT_EQ(report.number_of_issues(), 1u);
	EXPECT_EQ(report.to_string(), "Shift-reduce conflict of symbol ')' and rule 'E -> PE' in state 6");

	std::stringstream input1("(((a)))");
	auto result = p.parse(input1);
	EXPECT_TRUE(result);
	EXPECT_EQ(result.value(), (std::vector<std::string>{
		"PE -> a",
		"PE -> ( PE )",
		"PE -> ( PE )",
		"PE -> ( PE )",
		"E -> PE"
	}));
}

TEST_F(TestParser,
ResolveConflictWithPrecedence) {
	Parser<std::vector<std::string>> p;

	p.token("\\(").symbol("(");
	p.token("\\)").symbol(")").precedence(0, Associativity::Left);
	p.token("a").symbol("a");

	p.set_start_symbol("E");
	p.rule("E")
		.production("(", "E", ")", [](auto&& args) {
			args[1].push_back("E -> ( E )");
			return std::move(args[1]);
		})
		.production("PE", [](auto&& args) {
			args[0].push_back("E -> PE");
			return std::move(args[0]);
		}).precedence(1, Associativity::Left);
	p.rule("PE")
		.production("(", "PE", ")", [](auto&& args) {
			args[1].push_back("PE -> ( PE )");
			return std::move(args[1]);
		})
		.production("a", [](auto&&) {
			return std::vector<std::string>{"PE -> a"};
		});
	EXPECT_TRUE(p.prepare());

	std::stringstream input1("(((a)))");
	auto result = p.parse(input1);
	EXPECT_TRUE(result);
	EXPECT_EQ(result.value(), (std::vector<std::string>{
		"PE -> a",
		"E -> PE",
		"E -> ( E )",
		"E -> ( E )",
		"E -> ( E )"
	}));
}

TEST_F(TestParser,
MoveOnlyType) {
	Parser<std::unique_ptr<int>> p;

	p.token("a").symbol("a").action([](std::string_view) {
		return std::make_unique<int>(1);
	});

	p.set_start_symbol("A");
	p.rule("A")
		.production("A", "a", [](auto&& args) {
			*(args[0].get()) += 1;
			return std::move(args[0]);
		})
		.production("a", [](auto&& args) {
			return std::move(args[0]);
		});
	EXPECT_TRUE(p.prepare());

	std::stringstream input1("a");
	auto result = p.parse(input1);
	EXPECT_TRUE(result);
	EXPECT_EQ(*result.value().get(), 1);

	std::stringstream input2("aaaa");
	result = p.parse(input2);
	EXPECT_TRUE(result);
	EXPECT_EQ(*result.value().get(), 4);

	try
	{
		std::stringstream input3("aa aaa");
		p.parse(input3);
		FAIL() << "Expected syntax error";
	}
	catch (const SyntaxError& e)
	{
		EXPECT_STREQ(e.what(), "Syntax error: Unknown symbol on input, expected one of @end, a");
	}
}

TEST_F(TestParser,
EndTokenAction) {
	int end_call_count = 0;
	Parser<int> p;

	p.token("a").symbol("a");
	p.end_token().action([&](std::string_view) {
		end_call_count++;
		return 0;
	});

	p.set_start_symbol("A");
	p.rule("A")
		.production("A", "a", [](auto&& args) {
			return 1 + args[0];
		})
		.production("a", [](auto&&) {
			return 1;
		});
	EXPECT_TRUE(p.prepare());

	std::stringstream input1("aaaa");
	auto result = p.parse(input1);
	EXPECT_TRUE(result);
	EXPECT_EQ(result.value(), 4);
	EXPECT_EQ(end_call_count, 1);
}

TEST_F(TestParser,
TokenActionsCalledOnce) {
	int a_call_count = 0;
	Parser<int> p;

	p.token("a").symbol("a").action([&](std::string_view) {
		a_call_count++;
		return 0;
	});

	p.set_start_symbol("A");
	p.rule("A")
		.production("B", [](auto&& args) {
			return args[0];
		});
	p.rule("B")
		.production("A", "a", [](auto&& args) {
			return 1 + args[0];
		})
		.production("a", [](auto&&) {
			return 1;
		});
	EXPECT_TRUE(p.prepare());

	std::stringstream input1("aaaa");
	auto result = p.parse(input1);
	EXPECT_TRUE(result);
	EXPECT_EQ(result.value(), 4);
	EXPECT_EQ(a_call_count, 4);
}

TEST_F(TestParser,
MultistateTokenizer) {
	using Value = std::variant<
		std::string,
		std::pair<std::string, std::string>,
		std::vector<std::pair<std::string, std::string>>
	>;

	Parser<Value> p;
	std::string built_string;

	p.token("\\s+");
	p.token("=").symbol("=");
	p.token("[a-zA-Z_][a-zA-Z0-9_]*").symbol("id").action([](std::string_view str) -> Value {
		return std::string{str};
	});

	p.token(R"(")").enter_state("string").action([&](std::string_view) -> Value {
		built_string.clear();
		return {};
	});
	p.token(R"(\\n)").states("string").action([&](std::string_view) -> Value {
		built_string += '\n';
		return {};
	});
	p.token(R"(\\t)").states("string").action([&](std::string_view) -> Value {
		built_string += '\t';
		return {};
	});
	p.token(R"(\\r)").states("string").action([&](std::string_view) -> Value {
		built_string += '\r';
		return {};
	});
	p.token(R"(\\x[0-9a-fA-F]{2})").states("string").action([&](std::string_view str) -> Value {
		auto s = std::string{str.begin() + 2, str.end()};
		built_string += static_cast<char>(std::stoi(s, nullptr, 16));
		return {};
	});
	p.token(R"([^\\"]+)").states("string").action([&](std::string_view str) -> Value {
		built_string += str;
		return {};
	});
	p.token(R"(")").states("string").enter_state("@default").symbol("string_literal").action([&](std::string_view) -> Value {
		return built_string;
	});

	p.set_start_symbol("root");
	p.rule("root")
		.production("strings", [](auto&& args) -> Value {
			return std::move(args[0]);
		})
		.production([](auto&&) -> Value {
			return std::vector<std::pair<std::string, std::string>>{};
		});
	p.rule("strings")
		.production("strings", "string", [](auto&& args) -> Value {
			std::get<std::vector<std::pair<std::string, std::string>>>(args[0]).push_back(
				std::get<std::pair<std::string, std::string>>(args[1])
			);
			return std::move(args[0]);
		})
		.production("string", [](auto&& args) -> Value {
			return std::vector<std::pair<std::string, std::string>>{
				std::get<std::pair<std::string, std::string>>(args[0])
			};
		});
	p.rule("string")
		.production("id", "=", "string_literal", [](auto&& args) -> Value {
			return std::make_pair(
				std::get<std::string>(args[0]),
				std::get<std::string>(args[2])
			);
		});
	EXPECT_TRUE(p.prepare());

	std::stringstream input(
		"abc = \"xyz\"\n"
		"x = \"ab\\n\\t\\r\\x20cd\""
	);
	auto result = p.parse(input);
	EXPECT_TRUE(result);
	auto strings = std::get<std::vector<std::pair<std::string, std::string>>>(result.value());
	EXPECT_EQ(strings.size(), 2u);
	EXPECT_THAT(strings[0], Pair(Eq("abc"), Eq("xyz")));
	EXPECT_THAT(strings[1], Pair(Eq("x"), Eq("ab\n\t\r cd")));
}

TEST_F(TestParser,
MidruleActionsToCheckRedefinition) {
	using Value = std::variant<
		int,
		std::string
	>;

	Parser<Value> p;

	p.token("\\s+");
	p.token("=").symbol("=");
	p.token(";").symbol(";");
	p.token("\\{").symbol("{");
	p.token("\\}").symbol("}");
	p.token("function").symbol("function");
	p.token("var").symbol("var");
	p.token("[_a-zA-Z][_a-zA-Z0-9]*").symbol("id").action([](std::string_view str) -> Value {
		return std::string{str};
	});
	p.token("[0-9]+").symbol("num").action([](std::string_view str) -> Value {
		return std::stoi(std::string{str});
	});

	std::unordered_set<std::string> defs, redefs;

	p.set_start_symbol("prog");
	p.rule("prog")
		.production("funcs")
		.production();
	p.rule("funcs")
		.production("funcs", "func")
		.production("func");
	p.rule("func")
		.production(
			"function", "id", [&](auto&& args) -> Value {
				auto func_name = std::get<std::string>(args[1]);
				auto [itr, inserted] = defs.insert(func_name);
				if (!inserted)
					redefs.insert(func_name);
				return {};
			},
			"{", "func_body", "}"
		);
	p.rule("func_body")
		.production("stmts")
		.production();
	p.rule("stmts")
		.production("stmts", "stmt")
		.production("stmt");
	p.rule("stmt")
		.production(
			"var", "id", [&](auto&& args) -> Value {
				auto var_name = std::get<std::string>(args[1]);
				auto [itr, inserted] = defs.insert(var_name);
				if (!inserted)
					redefs.insert(var_name);
				return {};
			},
			"=", "num", ";"
		);
	EXPECT_TRUE(p.prepare());

	std::stringstream input1(
R"(function x {
	var y = 5;
	var z = 10;
})"
	);
	auto result1 = p.parse(input1);
	EXPECT_TRUE(result1);
	EXPECT_EQ(defs, (std::unordered_set<std::string>{"x", "y", "z"}));
	EXPECT_EQ(redefs, (std::unordered_set<std::string>{}));

	defs.clear();
	redefs.clear();

	std::stringstream input2(
R"(function x {
	var y = 5;
	var x = 10;
})"
	);
	auto result2 = p.parse(input2);
	EXPECT_TRUE(result2);
	EXPECT_EQ(defs, (std::unordered_set<std::string>{"x", "y"}));
	EXPECT_EQ(redefs, (std::unordered_set<std::string>{"x"}));

	defs.clear();
	redefs.clear();

	std::stringstream input3(
R"(function x {
	var y = 5;
	var z = 10;
}

function z {
	var a = 1;
})"
	);
	auto result3 = p.parse(input3);
	EXPECT_TRUE(result3);
	EXPECT_EQ(defs, (std::unordered_set<std::string>{"x", "y", "z", "a"}));
	EXPECT_EQ(redefs, (std::unordered_set<std::string>{"z"}));
}

TEST_F(TestParser,
InputStreamStackManipulation) {
	static std::vector<std::string> input_streams = {
		"10",
		"include 0",
		"30",
		"40"
	};

	std::vector<std::unique_ptr<std::stringstream>> inputs;

	Parser<int> p;

	p.token("\\s+");
	p.token("\\+").symbol("+").precedence(1, Associativity::Left);
	p.token("\\*").symbol("*").precedence(2, Associativity::Left);
	p.token("include [0-9]+").action([&](std::string_view str) {
		auto stream_idx = std::stoi(std::string{str.begin() + 8, str.end()});
		inputs.emplace_back(std::make_unique<std::stringstream>(input_streams[stream_idx]));
		p.push_input_stream(*inputs.back().get());
		return 0;
	});
	p.token("[0-9]+").symbol("number").action([](std::string_view str) {
		return std::stoi(std::string{str});
	});
	p.end_token().action([&](std::string_view) {
		p.pop_input_stream();
		return 0;
	});

	p.set_start_symbol("E");
	p.rule("E")
		.production("E", "+", "E", [](auto&& args) { return args[0] + args[2]; })
		.production("E", "*", "E", [](auto&& args) { return args[0] * args[2]; })
		.production("number", [](auto&& args) { return args[0]; });

	EXPECT_TRUE(p.prepare());

	std::stringstream input("include 1 + include 2 * include 3 + 5");
	auto result = p.parse(input);

	EXPECT_TRUE(result);
	EXPECT_EQ(result.value(), 1215);
}
