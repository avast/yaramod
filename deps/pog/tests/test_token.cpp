#include <gmock/gmock.h>

#include <pog/token.h>

using namespace pog;
using namespace ::testing;

class TestToken : public ::testing::Test {};

TEST_F(TestToken,
SimpleTokenWithoutSymbol) {
	Token<int> t(1, "abc");

	EXPECT_EQ(t.get_index(), 1u);
	EXPECT_EQ(t.get_pattern(), "abc");
	EXPECT_EQ(t.get_symbol(), nullptr);
	EXPECT_THAT(t.get_regexp(), A<const re2::RE2*>());

	EXPECT_FALSE(t.has_symbol());
	EXPECT_FALSE(t.has_action());
	EXPECT_FALSE(t.has_transition_to_state());
}

TEST_F(TestToken,
SimpleTokenWithSymbol) {
	Symbol<int> s(1, SymbolKind::Nonterminal, "a");
	Token<int> t(1, "abc", &s);

	EXPECT_EQ(t.get_index(), 1u);
	EXPECT_EQ(t.get_pattern(), "abc");
	EXPECT_EQ(t.get_symbol(), &s);
	EXPECT_THAT(t.get_regexp(), A<const re2::RE2*>());

	EXPECT_TRUE(t.has_symbol());
	EXPECT_FALSE(t.has_action());
	EXPECT_FALSE(t.has_transition_to_state());
}

TEST_F(TestToken,
TransitionToState) {
	Token<int> t(1, "abc");
	t.set_transition_to_state("dest_state");

	EXPECT_EQ(t.get_index(), 1u);
	EXPECT_EQ(t.get_pattern(), "abc");
	EXPECT_EQ(t.get_symbol(), nullptr);
	EXPECT_THAT(t.get_regexp(), A<const re2::RE2*>());

	EXPECT_FALSE(t.has_symbol());
	EXPECT_FALSE(t.has_action());
	EXPECT_TRUE(t.has_transition_to_state());
	EXPECT_EQ(t.get_transition_to_state(), "dest_state");
}

TEST_F(TestToken,
Action) {
	bool called = false;

	Token<int> t(1, "abc");
	t.set_action([&](std::string_view str) -> int {
		called = true;
		return static_cast<int>(str.length());
	});

	EXPECT_EQ(t.get_index(), 1u);
	EXPECT_TRUE(t.has_action());
	EXPECT_EQ(t.perform_action("abcdef"), 6);
	EXPECT_TRUE(called);
}
