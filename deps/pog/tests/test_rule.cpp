#include <gtest/gtest.h>

#include <pog/rule.h>

class TestRule : public ::testing::Test {};

using namespace pog;

TEST_F(TestRule,
SimpleRule) {
	Symbol<int> s1(1, SymbolKind::Nonterminal, "1");
	Symbol<int> s2(2, SymbolKind::Nonterminal, "2");
	Symbol<int> s3(3, SymbolKind::Nonterminal, "3");
	Rule<int> rule(42, &s1, std::vector<const Symbol<int>*>{&s2, &s3}, [](std::vector<int>&&) -> int { return 0; });

	EXPECT_EQ(rule.get_index(), 42u);
	EXPECT_EQ(rule.get_lhs(), &s1);
	EXPECT_EQ(rule.get_rhs(), (std::vector<const Symbol<int>*>{&s2, &s3}));
	EXPECT_FALSE(rule.has_precedence());
}

TEST_F(TestRule,
Precedence) {
	Symbol<int> s1(1, SymbolKind::Nonterminal, "1");
	Symbol<int> s2(2, SymbolKind::Nonterminal, "2");
	Symbol<int> s3(3, SymbolKind::Nonterminal, "3");
	Rule<int> rule(42, &s1, std::vector<const Symbol<int>*>{&s2, &s3}, [](std::vector<int>&&) -> int { return 0; });
	rule.set_precedence(1, Associativity::Right);

	EXPECT_EQ(rule.get_index(), 42u);
	EXPECT_EQ(rule.get_lhs(), &s1);
	EXPECT_EQ(rule.get_rhs(), (std::vector<const Symbol<int>*>{&s2, &s3}));
	EXPECT_TRUE(rule.has_precedence());
	EXPECT_EQ(rule.get_precedence(), (Precedence{1, Associativity::Right}));
}

TEST_F(TestRule,
RightmostTerminalWhileThereIsNone) {
	Symbol<int> s1(1, SymbolKind::Nonterminal, "1");
	Symbol<int> s2(2, SymbolKind::Nonterminal, "2");
	Symbol<int> s3(3, SymbolKind::Nonterminal, "3");
	Rule<int> rule(42, &s1, std::vector<const Symbol<int>*>{&s2, &s3}, [](std::vector<int>&&) -> int { return 0; });

	EXPECT_EQ(rule.get_rightmost_terminal(), nullptr);
}

TEST_F(TestRule,
RightmostTerminal) {
	Symbol<int> s1(1, SymbolKind::Nonterminal, "1");
	Symbol<int> s2(2, SymbolKind::Terminal, "2");
	Symbol<int> s3(3, SymbolKind::Terminal, "3");
	Symbol<int> s4(4, SymbolKind::Nonterminal, "4");
	Rule<int> rule(42, &s1, std::vector<const Symbol<int>*>{&s2, &s3, &s4}, [](std::vector<int>&&) -> int { return 0; });

	EXPECT_EQ(rule.get_rightmost_terminal(), &s3);
}

TEST_F(TestRule,
ToString) {
	Symbol<int> s1(1, SymbolKind::Nonterminal, "1");
	Symbol<int> s2(2, SymbolKind::Terminal, "2");
	Symbol<int> s3(3, SymbolKind::Terminal, "3");
	Symbol<int> s4(4, SymbolKind::Nonterminal, "4");
	Rule<int> rule(42, &s1, std::vector<const Symbol<int>*>{&s2, &s3, &s4}, [](std::vector<int>&&) -> int { return 0; });

	EXPECT_EQ(rule.to_string(), "1 -> 2 3 4");
}

TEST_F(TestRule,
EpsilonToString) {
	Symbol<int> s1(1, SymbolKind::Nonterminal, "1");
	Rule<int> rule(42, &s1, std::vector<const Symbol<int>*>{}, [](std::vector<int>&&) -> int { return 0; });

	EXPECT_EQ(rule.to_string(), "1 -> <eps>");
}

TEST_F(TestRule,
PerformAction) {
	bool called = false;

	Symbol<int> s1(1, SymbolKind::Nonterminal, "1");
	Rule<int> rule(42, &s1, std::vector<const Symbol<int>*>{}, [&](std::vector<int>&& args) -> int {
		called = true;
		return static_cast<int>(args.size());
	});

	EXPECT_EQ(rule.perform_action(std::vector<int>{1, 2, 3, 4}), 4);
	EXPECT_TRUE(called);
}

TEST_F(TestRule,
Equality) {
	Symbol<int> s1(1, SymbolKind::Nonterminal, "1");
	Symbol<int> s2(2, SymbolKind::Terminal, "2");
	Symbol<int> s3(3, SymbolKind::Terminal, "3");
	Symbol<int> s4(4, SymbolKind::Nonterminal, "4");
	Rule<int> rule1(42, &s1, std::vector<const Symbol<int>*>{&s2, &s3, &s4}, [](std::vector<int>&&) -> int { return 0; });
	Rule<int> rule2(42, &s1, std::vector<const Symbol<int>*>{}, [](std::vector<int>&&) -> int { return 0; });
	Rule<int> rule3(43, &s1, std::vector<const Symbol<int>*>{&s2, &s3, &s4}, [](std::vector<int>&&) -> int { return 0; });

	EXPECT_TRUE(rule1 == rule2);
	EXPECT_FALSE(rule1 == rule3);

	EXPECT_FALSE(rule1 != rule2);
	EXPECT_TRUE(rule1 != rule3);
}
