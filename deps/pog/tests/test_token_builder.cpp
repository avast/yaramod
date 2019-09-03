#include <gtest/gtest.h>

#include <pog/token_builder.h>

using namespace pog;

class TestTokenBuilder : public ::testing::Test
{
public:
	TestTokenBuilder() : grammar(), tokenizer(&grammar) {}

	Grammar<int> grammar;
	Tokenizer<int> tokenizer;
};

TEST_F(TestTokenBuilder,
Initialization) {
	TokenBuilder<int> tb(&grammar, &tokenizer);

	EXPECT_EQ(grammar.get_symbols().size(), 2u);
	EXPECT_EQ(tokenizer.get_tokens().size(), 1u);
}

TEST_F(TestTokenBuilder,
NoTokens) {
	TokenBuilder<int> tb(&grammar, &tokenizer);
	tb.done();

	EXPECT_EQ(grammar.get_symbols().size(), 2u);
	EXPECT_EQ(tokenizer.get_tokens().size(), 1u);
}

TEST_F(TestTokenBuilder,
SingleTokenWithoutAnything) {
	TokenBuilder<int> tb(&grammar, &tokenizer, "abc");
	tb.done();

	EXPECT_EQ(grammar.get_symbols().size(), 2u);
	EXPECT_EQ(tokenizer.get_tokens().size(), 2u);

	EXPECT_EQ(tokenizer.get_tokens()[1]->get_pattern(), "abc");
}

TEST_F(TestTokenBuilder,
SingleTokenWithSymbol) {
	TokenBuilder<int> tb(&grammar, &tokenizer, "abc");
	tb.symbol("ABC");
	tb.done();

	EXPECT_EQ(grammar.get_symbols().size(), 3u);
	EXPECT_EQ(tokenizer.get_tokens().size(), 2u);

	EXPECT_EQ(grammar.get_symbols()[2]->get_name(), "ABC");
	EXPECT_EQ(tokenizer.get_tokens()[1]->get_pattern(), "abc");
}

TEST_F(TestTokenBuilder,
SingleTokenWithAction) {
	TokenBuilder<int> tb(&grammar, &tokenizer, "abc");
	tb.action([](std::string_view) { return 42; });
	tb.done();

	EXPECT_EQ(grammar.get_symbols().size(), 2u);
	EXPECT_EQ(tokenizer.get_tokens().size(), 2u);

	EXPECT_EQ(tokenizer.get_tokens()[1]->get_pattern(), "abc");
	EXPECT_TRUE(tokenizer.get_tokens()[1]->has_action());
	EXPECT_EQ(tokenizer.get_tokens()[1]->perform_action("xyz"), 42);
}

TEST_F(TestTokenBuilder,
SingleTokenWithFullwordSpecifier) {
	TokenBuilder<int> tb(&grammar, &tokenizer, "abc");
	tb.fullword();
	tb.done();

	EXPECT_EQ(grammar.get_symbols().size(), 2u);
	EXPECT_EQ(tokenizer.get_tokens().size(), 2u);

	EXPECT_EQ(tokenizer.get_tokens()[1]->get_pattern(), "abc(\\b|$)");
}

TEST_F(TestTokenBuilder,
SingleTokenWithStates) {
	TokenBuilder<int> tb(&grammar, &tokenizer, "abc");
	tb.states("state1", "state2");
	tb.done();

	EXPECT_EQ(grammar.get_symbols().size(), 2u);
	EXPECT_EQ(tokenizer.get_tokens().size(), 2u);

	EXPECT_EQ(tokenizer.get_tokens()[1]->get_pattern(), "abc");
}

TEST_F(TestTokenBuilder,
SingleTokenWithTransitionToState) {
	TokenBuilder<int> tb(&grammar, &tokenizer, "abc");
	tb.enter_state("state1");
	tb.done();

	EXPECT_EQ(grammar.get_symbols().size(), 2u);
	EXPECT_EQ(tokenizer.get_tokens().size(), 2u);

	EXPECT_EQ(tokenizer.get_tokens()[1]->get_pattern(), "abc");
	EXPECT_TRUE(tokenizer.get_tokens()[1]->has_transition_to_state());
	EXPECT_EQ(tokenizer.get_tokens()[1]->get_transition_to_state(), "state1");
}

TEST_F(TestTokenBuilder,
SingleTokenWithPrecedence) {
	TokenBuilder<int> tb(&grammar, &tokenizer, "abc");
	tb.symbol("ABC");
	tb.precedence(1, Associativity::Left);
	tb.done();

	EXPECT_EQ(grammar.get_symbols().size(), 3u);
	EXPECT_EQ(tokenizer.get_tokens().size(), 2u);

	EXPECT_EQ(tokenizer.get_tokens()[1]->get_pattern(), "abc");
	EXPECT_TRUE(grammar.get_symbols()[2]->has_precedence());
	EXPECT_EQ(grammar.get_symbols()[2]->get_precedence(), (Precedence{1, Associativity::Left}));
}
