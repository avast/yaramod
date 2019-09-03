#include <gtest/gtest.h>

#include <pog/symbol.h>

class TestSymbol : public ::testing::Test {};

using namespace pog;

TEST_F(TestSymbol,
Nonterminal) {
	Symbol<int> symbol(42, SymbolKind::Nonterminal, "testing_nonterminal");

	EXPECT_EQ(symbol.get_index(), 42u);
	EXPECT_EQ(symbol.get_name(), "testing_nonterminal");
	EXPECT_FALSE(symbol.is_end());
	EXPECT_TRUE(symbol.is_nonterminal());
	EXPECT_FALSE(symbol.is_terminal());
	EXPECT_FALSE(symbol.has_precedence());
}

TEST_F(TestSymbol,
Terminal) {
	Symbol<int> symbol(42, SymbolKind::Terminal, "testing_terminal");

	EXPECT_EQ(symbol.get_index(), 42u);
	EXPECT_EQ(symbol.get_name(), "testing_terminal");
	EXPECT_FALSE(symbol.is_end());
	EXPECT_FALSE(symbol.is_nonterminal());
	EXPECT_TRUE(symbol.is_terminal());
	EXPECT_FALSE(symbol.has_precedence());
}

TEST_F(TestSymbol,
End) {
	Symbol<int> symbol(42, SymbolKind::End, "testing_end");

	EXPECT_EQ(symbol.get_index(), 42u);
	EXPECT_EQ(symbol.get_name(), "testing_end");
	EXPECT_TRUE(symbol.is_end());
	EXPECT_FALSE(symbol.is_nonterminal());
	EXPECT_FALSE(symbol.is_terminal());
	EXPECT_FALSE(symbol.has_precedence());
}

TEST_F(TestSymbol,
Precedence) {
	Symbol<int> symbol(42, SymbolKind::Terminal, "testing_terminal");
	symbol.set_precedence(1, Associativity::Right);

	EXPECT_EQ(symbol.get_index(), 42u);
	EXPECT_EQ(symbol.get_name(), "testing_terminal");
	EXPECT_FALSE(symbol.is_end());
	EXPECT_FALSE(symbol.is_nonterminal());
	EXPECT_TRUE(symbol.is_terminal());
	EXPECT_TRUE(symbol.has_precedence());
	EXPECT_EQ(symbol.get_precedence(), (Precedence{1, Associativity::Right}));
}
