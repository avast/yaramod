#include <gtest/gtest.h>

#include <pog/grammar.h>

using namespace pog;

class TestGrammar : public ::testing::Test {};

TEST_F(TestGrammar,
DefaultGrammar) {
	Grammar<int> g;

	EXPECT_EQ(g.get_symbols().size(), 2u);
	EXPECT_EQ(g.get_rules().size(), 0u);

	EXPECT_TRUE(g.get_symbols()[0]->is_nonterminal());
	EXPECT_EQ(g.get_symbols()[0]->get_name(), "@start");

	EXPECT_TRUE(g.get_symbols()[1]->is_end());
	EXPECT_EQ(g.get_symbols()[1]->get_name(), "@end");

	EXPECT_EQ(g.get_end_of_input_symbol(), g.get_symbols()[1].get());
	EXPECT_EQ(g.get_start_rule(), nullptr);
}

TEST_F(TestGrammar,
AddSymbol) {
	Grammar<int> g;

	g.add_symbol(SymbolKind::Nonterminal, "A");
	g.add_symbol(SymbolKind::Nonterminal, "B");

	EXPECT_EQ(g.get_symbols().size(), 4u);
}

TEST_F(TestGrammar,
AddSymbolDuplicate) {
	Grammar<int> g;

	g.add_symbol(SymbolKind::Nonterminal, "A");
	g.add_symbol(SymbolKind::Terminal, "A");

	EXPECT_EQ(g.get_symbols().size(), 3u);
}

TEST_F(TestGrammar,
GetSymbol) {
	Grammar<int> g;

	auto sym = g.add_symbol(SymbolKind::Nonterminal, "A");
	EXPECT_EQ(g.get_symbol("A"), sym);
	EXPECT_EQ(g.get_symbol("B"), nullptr);
}

TEST_F(TestGrammar,
AddRule) {
	Grammar<int> g;

	auto s1 = g.add_symbol(SymbolKind::Nonterminal, "A");
	auto s2 = g.add_symbol(SymbolKind::Nonterminal, "B");
	auto s3 = g.add_symbol(SymbolKind::Nonterminal, "C");

	auto result = g.add_rule(s1, std::vector<const Symbol<int>*>{s2, s3}, [](auto&&) -> int { return 0; });
	EXPECT_EQ(g.get_rules().size(), 1u);
	EXPECT_EQ(result->get_lhs(), s1);
	EXPECT_EQ(result->get_rhs(), (std::vector<const Symbol<int>*>{s2, s3}));
}

TEST_F(TestGrammar,
GetRulesOfSymbol) {
	Grammar<int> g;

	auto s1 = g.add_symbol(SymbolKind::Nonterminal, "A");
	auto s2 = g.add_symbol(SymbolKind::Nonterminal, "B");
	auto s3 = g.add_symbol(SymbolKind::Nonterminal, "C");

	auto r1 = g.add_rule(s1, std::vector<const Symbol<int>*>{s2, s3}, [](auto&&) -> int { return 0; });
	auto r2 = g.add_rule(s1, std::vector<const Symbol<int>*>{}, [](auto&&) -> int { return 0; });
	auto r3 = g.add_rule(s2, std::vector<const Symbol<int>*>{s1, s3}, [](auto&&) -> int { return 0; });

	EXPECT_EQ(g.get_rules().size(), 3u);
	EXPECT_EQ(g.get_rules_of_symbol(s1), (std::vector<const Rule<int>*>{r1, r2}));
	EXPECT_EQ(g.get_rules_of_symbol(s2), (std::vector<const Rule<int>*>{r3}));
	EXPECT_EQ(g.get_rules_of_symbol(s3), (std::vector<const Rule<int>*>{}));
}

TEST_F(TestGrammar,
GetRulesWithSymbol) {
	Grammar<int> g;

	auto s1 = g.add_symbol(SymbolKind::Nonterminal, "A");
	auto s2 = g.add_symbol(SymbolKind::Nonterminal, "B");
	auto s3 = g.add_symbol(SymbolKind::Nonterminal, "C");

	auto r1 = g.add_rule(s1, std::vector<const Symbol<int>*>{s2, s3}, [](auto&&) -> int { return 0; });
	auto r2 = g.add_rule(s1, std::vector<const Symbol<int>*>{}, [](auto&&) -> int { return 0; });
	auto r3 = g.add_rule(s2, std::vector<const Symbol<int>*>{s1, s3}, [](auto&&) -> int { return 0; });
	static_cast<void>(r2);

	EXPECT_EQ(g.get_rules().size(), 3u);
	EXPECT_EQ(g.get_rules_with_symbol(s1), (std::vector<const Rule<int>*>{r3}));
	EXPECT_EQ(g.get_rules_with_symbol(s2), (std::vector<const Rule<int>*>{r1}));
	EXPECT_EQ(g.get_rules_with_symbol(s3), (std::vector<const Rule<int>*>{r1, r3}));
}

TEST_F(TestGrammar,
StartSymbol) {
	Grammar<int> g;

	auto s = g.add_symbol(SymbolKind::Nonterminal, "A");
	g.set_start_symbol(s);

	EXPECT_EQ(g.get_rules().size(), 1u);
	EXPECT_EQ(g.get_rules()[0]->to_string(), "@start -> A @end");
	EXPECT_EQ(g.get_rules()[0].get(), g.get_start_rule());
}

TEST_F(TestGrammar,
Empty) {
	Grammar<int> g;

	auto a = g.add_symbol(SymbolKind::Terminal, "a");
	auto b = g.add_symbol(SymbolKind::Terminal, "b");
	auto S = g.add_symbol(SymbolKind::Nonterminal, "S");
	auto A = g.add_symbol(SymbolKind::Nonterminal, "A");

	g.add_rule(S, std::vector<const Symbol<int>*>{a, S, b}, [](auto&&) -> int { return 0; });
	g.add_rule(S, std::vector<const Symbol<int>*>{a, b}, [](auto&&) -> int { return 0; });
	g.add_rule(A, std::vector<const Symbol<int>*>{a}, [](auto&&) -> int { return 0; });
	g.add_rule(A, std::vector<const Symbol<int>*>{}, [](auto&&) -> int { return 0; });

	EXPECT_FALSE(g.empty(a));
	EXPECT_FALSE(g.empty(b));
	EXPECT_FALSE(g.empty(S));
	EXPECT_TRUE(g.empty(A));

	EXPECT_TRUE(g.empty(std::vector<const Symbol<int>*>{A, A, A}));
	EXPECT_FALSE(g.empty(std::vector<const Symbol<int>*>{A, A, A, S}));
}

TEST_F(TestGrammar,
First) {
	Grammar<int> g;

	auto a = g.add_symbol(SymbolKind::Terminal, "a");
	auto b = g.add_symbol(SymbolKind::Terminal, "b");
	auto S = g.add_symbol(SymbolKind::Nonterminal, "S");
	auto A = g.add_symbol(SymbolKind::Nonterminal, "A");

	g.add_rule(S, std::vector<const Symbol<int>*>{a, S, b}, [](auto&&) -> int { return 0; });
	g.add_rule(S, std::vector<const Symbol<int>*>{a, b}, [](auto&&) -> int { return 0; });
	g.add_rule(S, std::vector<const Symbol<int>*>{b}, [](auto&&) -> int { return 0; });
	g.add_rule(A, std::vector<const Symbol<int>*>{a}, [](auto&&) -> int { return 0; });
	g.add_rule(A, std::vector<const Symbol<int>*>{}, [](auto&&) -> int { return 0; });

	EXPECT_EQ(g.first(a), (std::unordered_set<const Symbol<int>*>{a}));
	EXPECT_EQ(g.first(b), (std::unordered_set<const Symbol<int>*>{b}));
	EXPECT_EQ(g.first(S), (std::unordered_set<const Symbol<int>*>{a, b}));
	EXPECT_EQ(g.first(A), (std::unordered_set<const Symbol<int>*>{a}));

	EXPECT_EQ(g.first(std::vector<const Symbol<int>*>{A, A, A}), (std::unordered_set<const Symbol<int>*>{a}));
	EXPECT_EQ(g.first(std::vector<const Symbol<int>*>{A, A, A, S}), (std::unordered_set<const Symbol<int>*>{a, b}));
	EXPECT_EQ(g.first(std::vector<const Symbol<int>*>{b, A, A, S}), (std::unordered_set<const Symbol<int>*>{b}));
}

TEST_F(TestGrammar,
Follow) {
	Grammar<int> g;

	auto a = g.add_symbol(SymbolKind::Terminal, "a");
	auto b = g.add_symbol(SymbolKind::Terminal, "b");
	auto S = g.add_symbol(SymbolKind::Nonterminal, "S");
	auto A = g.add_symbol(SymbolKind::Nonterminal, "A");

	g.add_rule(S, std::vector<const Symbol<int>*>{a, S, b}, [](auto&&) -> int { return 0; });
	g.add_rule(S, std::vector<const Symbol<int>*>{a, b}, [](auto&&) -> int { return 0; });
	g.add_rule(S, std::vector<const Symbol<int>*>{b}, [](auto&&) -> int { return 0; });
	g.add_rule(A, std::vector<const Symbol<int>*>{a, A}, [](auto&&) -> int { return 0; });
	g.add_rule(A, std::vector<const Symbol<int>*>{}, [](auto&&) -> int { return 0; });

	EXPECT_EQ(g.follow(S), (std::unordered_set<const Symbol<int>*>{b}));
	EXPECT_EQ(g.follow(A), (std::unordered_set<const Symbol<int>*>{}));

	// To test out caching
	EXPECT_EQ(g.follow(S), (std::unordered_set<const Symbol<int>*>{b}));
	EXPECT_EQ(g.follow(A), (std::unordered_set<const Symbol<int>*>{}));
}
