#include <gtest/gtest.h>

#include <pog/tokenizer.h>

using namespace pog;

class TestTokenizer : public ::testing::Test
{
public:
	Grammar<int> grammar;
};

TEST_F(TestTokenizer,
Initialization) {
	Tokenizer<int> t(&grammar);

	EXPECT_EQ(t.get_tokens().size(), 1u);
	EXPECT_EQ(t.get_tokens()[0].get(), t.get_end_token());
	EXPECT_FALSE(t.get_tokens()[0]->has_symbol());
}

TEST_F(TestTokenizer,
AddToken) {
	auto a = grammar.add_symbol(SymbolKind::Terminal, "a");
	auto b = grammar.add_symbol(SymbolKind::Terminal, "b");

	Tokenizer<int> t(&grammar);

	t.add_token("aaa", a, std::vector<std::string>{std::string{decltype(t)::DefaultState}});
	t.add_token("bbb", b, std::vector<std::string>{std::string{decltype(t)::DefaultState}});
	t.add_token("ccc", nullptr, std::vector<std::string>{std::string{decltype(t)::DefaultState}});

	EXPECT_EQ(t.get_tokens().size(), 4u);
	EXPECT_EQ(t.get_tokens()[1]->get_pattern(), "aaa");
	EXPECT_TRUE(t.get_tokens()[1]->has_symbol());
	EXPECT_EQ(t.get_tokens()[1]->get_symbol(), a);
	EXPECT_EQ(t.get_tokens()[2]->get_pattern(), "bbb");
	EXPECT_TRUE(t.get_tokens()[2]->has_symbol());
	EXPECT_EQ(t.get_tokens()[2]->get_symbol(), b);
	EXPECT_EQ(t.get_tokens()[3]->get_pattern(), "ccc");
	EXPECT_FALSE(t.get_tokens()[3]->has_symbol());
}

TEST_F(TestTokenizer,
NextToken) {
	auto a = grammar.add_symbol(SymbolKind::Terminal, "a");
	auto b = grammar.add_symbol(SymbolKind::Terminal, "b");

	Tokenizer<int> t(&grammar);

	t.add_token("aaa", a, std::vector<std::string>{std::string{decltype(t)::DefaultState}});
	t.add_token("bbb", b, std::vector<std::string>{std::string{decltype(t)::DefaultState}});
	t.add_token("ccc", nullptr, std::vector<std::string>{std::string{decltype(t)::DefaultState}});
	t.prepare();

	std::stringstream input("aaacccbbb");
	t.push_input_stream(input);

	auto result = t.next_token();
	EXPECT_TRUE(result);
	EXPECT_EQ(result.value().symbol, a);

	result = t.next_token();
	EXPECT_TRUE(result);
	EXPECT_EQ(result.value().symbol, b);

	result = t.next_token();
	EXPECT_TRUE(result);
	EXPECT_EQ(result.value().symbol, grammar.get_end_of_input_symbol());
}

TEST_F(TestTokenizer,
NextTokenWithUnknownToken) {
	auto a = grammar.add_symbol(SymbolKind::Terminal, "a");
	auto b = grammar.add_symbol(SymbolKind::Terminal, "b");

	Tokenizer<int> t(&grammar);

	t.add_token("aaa", a, std::vector<std::string>{std::string{decltype(t)::DefaultState}});
	t.add_token("bbb", b, std::vector<std::string>{std::string{decltype(t)::DefaultState}});
	t.add_token("ccc", nullptr, std::vector<std::string>{std::string{decltype(t)::DefaultState}});
	t.prepare();

	std::stringstream input("aaaccbbb");
	t.push_input_stream(input);

	auto result = t.next_token();
	EXPECT_TRUE(result);
	EXPECT_EQ(result.value().symbol, a);

	result = t.next_token();
	EXPECT_FALSE(result);
}

TEST_F(TestTokenizer,
NextTokenLongestMatchWins) {
	auto a1 = grammar.add_symbol(SymbolKind::Terminal, "a1");
	auto a2 = grammar.add_symbol(SymbolKind::Terminal, "a3");
	auto a3 = grammar.add_symbol(SymbolKind::Terminal, "a3");

	Tokenizer<int> t(&grammar);

	t.add_token("a", a1, std::vector<std::string>{std::string{decltype(t)::DefaultState}});
	t.add_token("aaa", a3, std::vector<std::string>{std::string{decltype(t)::DefaultState}});
	t.add_token("aa", a2, std::vector<std::string>{std::string{decltype(t)::DefaultState}});
	t.prepare();

	std::stringstream input("aaaaa");
	t.push_input_stream(input);

	auto result = t.next_token();
	EXPECT_TRUE(result);
	EXPECT_EQ(result.value().symbol, a3);
}

TEST_F(TestTokenizer,
NextTokenIndexWinsInCaseOfEqualMatch) {
	auto a3 = grammar.add_symbol(SymbolKind::Terminal, "a3");
	auto an = grammar.add_symbol(SymbolKind::Terminal, "an");

	Tokenizer<int> t(&grammar);

	t.add_token("aaa", a3, std::vector<std::string>{std::string{decltype(t)::DefaultState}});
	t.add_token("a*", an, std::vector<std::string>{std::string{decltype(t)::DefaultState}});
	t.prepare();

	std::stringstream input("aaa");
	t.push_input_stream(input);

	auto result = t.next_token();
	EXPECT_TRUE(result);
	EXPECT_EQ(result.value().symbol, a3);
}

TEST_F(TestTokenizer,
TokenActionsPerformed) {
	auto a = grammar.add_symbol(SymbolKind::Terminal, "a");
	auto b = grammar.add_symbol(SymbolKind::Terminal, "b");

	Tokenizer<int> t(&grammar);

	std::vector<std::string> matches;

	auto a_t = t.add_token("a+", a, std::vector<std::string>{std::string{decltype(t)::DefaultState}});
	a_t->set_action([&](std::string_view str) {
		matches.push_back(std::string{str});
		return 0;
	});
	auto b_t = t.add_token("b+", b, std::vector<std::string>{std::string{decltype(t)::DefaultState}});
	b_t->set_action([&](std::string_view str) {
		matches.push_back(std::string{str});
		return 0;
	});
	t.get_end_token()->set_action([&](std::string_view str) {
		matches.push_back(std::string{str});
		return 0;
	});
	t.prepare();

	std::stringstream input("aabbbbaaaaabb");
	t.push_input_stream(input);

	for (auto i = 0; i < 5; ++i)
		t.next_token();

	EXPECT_EQ(matches.size(), 5u);
	EXPECT_EQ(matches, (std::vector<std::string>{"aa", "bbbb", "aaaaa", "bb", ""}));
}

TEST_F(TestTokenizer,
InputStreamStackManipulation) {
	auto a = grammar.add_symbol(SymbolKind::Terminal, "a");
	auto b = grammar.add_symbol(SymbolKind::Terminal, "b");

	Tokenizer<int> t(&grammar);

	t.add_token("aaa", a, std::vector<std::string>{std::string{decltype(t)::DefaultState}});
	t.add_token("bbb", b, std::vector<std::string>{std::string{decltype(t)::DefaultState}});
	t.prepare();

	std::stringstream input("aaabbb");
	t.push_input_stream(input);

	auto result = t.next_token();
	EXPECT_TRUE(result);
	EXPECT_EQ(result.value().symbol, a);

	std::stringstream input2("aaaaaa");
	t.push_input_stream(input2);

	result = t.next_token();
	EXPECT_TRUE(result);
	EXPECT_EQ(result.value().symbol, a);

	result = t.next_token();
	EXPECT_TRUE(result);
	EXPECT_EQ(result.value().symbol, a);

	result = t.next_token();
	EXPECT_TRUE(result);
	EXPECT_EQ(result.value().symbol, grammar.get_end_of_input_symbol());

	t.pop_input_stream();

	result = t.next_token();
	EXPECT_TRUE(result);
	EXPECT_EQ(result.value().symbol, b);

	result = t.next_token();
	EXPECT_TRUE(result);
	EXPECT_EQ(result.value().symbol, grammar.get_end_of_input_symbol());
}

TEST_F(TestTokenizer,
StatesAndTransitions) {
	auto a = grammar.add_symbol(SymbolKind::Terminal, "a");
	auto b = grammar.add_symbol(SymbolKind::Terminal, "b");

	Tokenizer<int> t(&grammar);

	auto a_t = t.add_token("aaa", a, std::vector<std::string>{std::string{decltype(t)::DefaultState}});
	auto b_t = t.add_token("bbb", b, std::vector<std::string>{"state1"});
	a_t->set_transition_to_state("state1");
	b_t->set_transition_to_state(std::string{decltype(t)::DefaultState});
	t.prepare();

	std::stringstream input("aaabbb");
	t.push_input_stream(input);
	EXPECT_TRUE(t.next_token());
	EXPECT_TRUE(t.next_token());
	EXPECT_TRUE(t.next_token());
	t.pop_input_stream();

	std::stringstream input2("aaaaaa");
	t.push_input_stream(input2);
	EXPECT_TRUE(t.next_token());
	EXPECT_FALSE(t.next_token());
	t.pop_input_stream();
}
