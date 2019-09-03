#include <gmock/gmock.h>

#include <pog/state.h>

using namespace pog;
using namespace ::testing;

class TestState : public ::testing::Test {};

TEST_F(TestState,
DefultState) {
	State<int> state;

	EXPECT_EQ(state.get_index(), std::numeric_limits<std::uint32_t>::max());
}

TEST_F(TestState,
SimpleState) {
	Symbol<int> s1(1, SymbolKind::Nonterminal, "1");
	Symbol<int> s2(2, SymbolKind::Nonterminal, "2");
	Symbol<int> s3(3, SymbolKind::Nonterminal, "3");
	Rule<int> rule(42, &s1, std::vector<const Symbol<int>*>{&s2, &s3}, [](std::vector<int>&&) -> int { return 0; });

	State<int> state(1);

	EXPECT_EQ(state.get_index(), 1u);
	EXPECT_EQ(state.size(), 0u);
}

TEST_F(TestState,
SetIndex) {
	Symbol<int> s1(1, SymbolKind::Nonterminal, "1");
	Symbol<int> s2(2, SymbolKind::Nonterminal, "2");
	Symbol<int> s3(3, SymbolKind::Nonterminal, "3");
	Rule<int> rule(42, &s1, std::vector<const Symbol<int>*>{&s2, &s3}, [](std::vector<int>&&) -> int { return 0; });

	State<int> state(1);
	state.set_index(2);

	EXPECT_EQ(state.get_index(), 2u);
	EXPECT_EQ(state.size(), 0u);
}

TEST_F(TestState,
AddItem) {
	Symbol<int> s1(1, SymbolKind::Nonterminal, "1");
	Symbol<int> s2(2, SymbolKind::Nonterminal, "2");
	Symbol<int> s3(3, SymbolKind::Nonterminal, "3");
	Rule<int> rule1(42, &s1, std::vector<const Symbol<int>*>{&s2, &s3}, [](std::vector<int>&&) -> int { return 0; });
	Rule<int> rule2(43, &s1, std::vector<const Symbol<int>*>{&s2}, [](std::vector<int>&&) -> int { return 0; });

	State<int> state(1);
	auto result1 = state.add_item(Item<int>{&rule1, 0});
	auto result2 = state.add_item(Item<int>{&rule2, 0});
	EXPECT_EQ(state.size(), 2u);
	EXPECT_THAT(result1, Pair(An<const Item<int>*>(), Eq(true)));
	EXPECT_THAT(result2, Pair(An<const Item<int>*>(), Eq(true)));
	EXPECT_NE(result1.first, result2.first);
}

TEST_F(TestState,
AddItemAlreadyExists) {
	Symbol<int> s1(1, SymbolKind::Nonterminal, "1");
	Symbol<int> s2(2, SymbolKind::Nonterminal, "2");
	Symbol<int> s3(3, SymbolKind::Nonterminal, "3");
	Rule<int> rule1(42, &s1, std::vector<const Symbol<int>*>{&s2, &s3}, [](std::vector<int>&&) -> int { return 0; });
	Rule<int> rule2(42, &s1, std::vector<const Symbol<int>*>{&s2, &s3}, [](std::vector<int>&&) -> int { return 0; });

	State<int> state(1);
	auto result1 = state.add_item(Item<int>{&rule1, 0});
	auto result2 = state.add_item(Item<int>{&rule2, 0});
	EXPECT_EQ(state.size(), 1u);
	EXPECT_THAT(result1, Pair(An<const Item<int>*>(), Eq(true)));
	EXPECT_THAT(result2, Pair(An<const Item<int>*>(), Eq(false)));
	EXPECT_EQ(result1.first, result2.first);
}

TEST_F(TestState,
ItemsAreSorted) {
	Symbol<int> s1(1, SymbolKind::Nonterminal, "1");
	Symbol<int> s2(2, SymbolKind::Nonterminal, "2");
	Symbol<int> s3(3, SymbolKind::Nonterminal, "3");
	Rule<int> rule1(44, &s1, std::vector<const Symbol<int>*>{}, [](std::vector<int>&&) -> int { return 0; });
	Rule<int> rule2(43, &s1, std::vector<const Symbol<int>*>{&s2}, [](std::vector<int>&&) -> int { return 0; });
	Rule<int> rule3(42, &s1, std::vector<const Symbol<int>*>{&s2, &s3}, [](std::vector<int>&&) -> int { return 0; });

	State<int> state(1);
	state.add_item(Item<int>{&rule1, 0});
	state.add_item(Item<int>{&rule2, 0});
	state.add_item(Item<int>{&rule3, 0});
	EXPECT_EQ(state.size(), 3u);
	EXPECT_EQ(state.begin()->get()->get_rule()->get_index(), 42u);
	EXPECT_EQ((state.begin() + 1)->get()->get_rule()->get_index(), 43u);
	EXPECT_EQ((state.begin() + 2)->get()->get_rule()->get_index(), 44u);
}

TEST_F(TestState,
ItemAreIterable) {
	Symbol<int> s1(1, SymbolKind::Nonterminal, "1");
	Symbol<int> s2(2, SymbolKind::Nonterminal, "2");
	Symbol<int> s3(3, SymbolKind::Nonterminal, "3");
	Rule<int> rule1(44, &s1, std::vector<const Symbol<int>*>{}, [](std::vector<int>&&) -> int { return 0; });
	Rule<int> rule2(43, &s1, std::vector<const Symbol<int>*>{&s2}, [](std::vector<int>&&) -> int { return 0; });
	Rule<int> rule3(42, &s1, std::vector<const Symbol<int>*>{&s2, &s3}, [](std::vector<int>&&) -> int { return 0; });

	State<int> state(1);
	auto result1 = state.add_item(Item<int>{&rule1, 0});
	auto result2 = state.add_item(Item<int>{&rule2, 0});
	auto result3 = state.add_item(Item<int>{&rule3, 0});

	auto expected = std::vector<const Item<int>*>{result3.first, result2.first, result1.first};
	std::size_t i = 0;
	for (const auto& item : state)
		EXPECT_EQ(item.get(), expected[i++]);
}

TEST_F(TestState,
AddTransition) {
	Symbol<int> s1(1, SymbolKind::Nonterminal, "1");
	Symbol<int> s2(2, SymbolKind::Nonterminal, "2");
	Symbol<int> s3(3, SymbolKind::Nonterminal, "3");
	Rule<int> rule1(42, &s1, std::vector<const Symbol<int>*>{}, [](std::vector<int>&&) -> int { return 0; });
	Rule<int> rule2(43, &s1, std::vector<const Symbol<int>*>{&s2}, [](std::vector<int>&&) -> int { return 0; });
	Rule<int> rule3(44, &s1, std::vector<const Symbol<int>*>{&s2, &s3}, [](std::vector<int>&&) -> int { return 0; });

	State<int> state1(1);
	state1.add_item(Item<int>{&rule1, 0});
	State<int> state2(2);
	state2.add_item(Item<int>{&rule2, 0});

	state1.add_transition(&s1, &state2);

	EXPECT_EQ(state1.get_transitions().size(), 1u);
	auto itr = state1.get_transitions().find(&s1);
	EXPECT_NE(itr, state1.get_transitions().end());
	EXPECT_EQ(itr->second, &state2);
}

TEST_F(TestState,
AddBackTransition) {
	Symbol<int> s1(1, SymbolKind::Nonterminal, "1");
	Symbol<int> s2(2, SymbolKind::Nonterminal, "2");
	Symbol<int> s3(3, SymbolKind::Nonterminal, "3");
	Rule<int> rule1(42, &s1, std::vector<const Symbol<int>*>{}, [](std::vector<int>&&) -> int { return 0; });
	Rule<int> rule2(43, &s1, std::vector<const Symbol<int>*>{&s2}, [](std::vector<int>&&) -> int { return 0; });
	Rule<int> rule3(44, &s1, std::vector<const Symbol<int>*>{&s2, &s3}, [](std::vector<int>&&) -> int { return 0; });

	State<int> state1(1);
	state1.add_item(Item<int>{&rule1, 0});
	State<int> state2(30);
	state2.add_item(Item<int>{&rule2, 0});
	State<int> state3(20);
	state2.add_item(Item<int>{&rule3, 0});

	state1.add_back_transition(&s1, &state2);
	state1.add_back_transition(&s1, &state3);

	EXPECT_EQ(state1.get_back_transitions().size(), 1u);
	auto itr = state1.get_back_transitions().find(&s1);
	EXPECT_NE(itr, state1.get_back_transitions().end());
	EXPECT_EQ(itr->second, (std::vector<const State<int>*>{&state3, &state2}));
}

TEST_F(TestState,
IsAccepting) {
	Symbol<int> s1(1, SymbolKind::Nonterminal, "1");
	Symbol<int> s2(2, SymbolKind::Nonterminal, "2");
	Symbol<int> s3(3, SymbolKind::End, "3");
	Rule<int> rule1(42, &s1, std::vector<const Symbol<int>*>{}, [](std::vector<int>&&) -> int { return 0; });
	Rule<int> rule2(43, &s1, std::vector<const Symbol<int>*>{&s2, &s3}, [](std::vector<int>&&) -> int { return 0; });

	State<int> state1(1);
	state1.add_item(Item<int>{&rule1, 0});
	State<int> state2(2);
	state2.add_item(Item<int>{&rule2, 0});
	State<int> state3(3);
	state3.add_item(Item<int>{&rule2, 1});

	EXPECT_FALSE(state1.is_accepting());
	EXPECT_FALSE(state2.is_accepting());
	EXPECT_TRUE(state3.is_accepting());
}

TEST_F(TestState,
ToString) {
	Symbol<int> s1(1, SymbolKind::Nonterminal, "1");
	Symbol<int> s2(2, SymbolKind::Nonterminal, "2");
	Symbol<int> s3(3, SymbolKind::End, "3");
	Rule<int> rule1(42, &s1, std::vector<const Symbol<int>*>{}, [](std::vector<int>&&) -> int { return 0; });
	Rule<int> rule2(43, &s1, std::vector<const Symbol<int>*>{&s2, &s3}, [](std::vector<int>&&) -> int { return 0; });

	State<int> state(1);
	state.add_item(Item<int>{&rule1, 0});
	state.add_item(Item<int>{&rule2, 0});
	state.add_item(Item<int>{&rule2, 1});

	EXPECT_EQ(state.to_string(), "1 -> 2 <*> 3\n1 -> <*> <eps>\n1 -> <*> 2 3");
}

TEST_F(TestState,
GetProductionItems) {
	Symbol<int> s1(1, SymbolKind::Nonterminal, "1");
	Symbol<int> s2(2, SymbolKind::Nonterminal, "2");
	Symbol<int> s3(3, SymbolKind::End, "3");
	Rule<int> rule(43, &s1, std::vector<const Symbol<int>*>{&s2, &s3}, [](std::vector<int>&&) -> int { return 0; });

	State<int> state(1);
	state.add_item(Item<int>{&rule, 0});
	state.add_item(Item<int>{&rule, 1});

	auto expected = std::vector<const Item<int>*>{};
	EXPECT_EQ(state.get_production_items(), expected);

	auto i = state.add_item(Item<int>{&rule, 2});
	expected.push_back(i.first);
	EXPECT_EQ(state.get_production_items(), expected);
}

TEST_F(TestState,
Contains) {
	Symbol<int> s1(1, SymbolKind::Nonterminal, "1");
	Symbol<int> s2(2, SymbolKind::Nonterminal, "2");
	Symbol<int> s3(3, SymbolKind::End, "3");
	Rule<int> rule(43, &s1, std::vector<const Symbol<int>*>{&s2, &s3}, [](std::vector<int>&&) -> int { return 0; });

	State<int> state(1);
	state.add_item(Item<int>{&rule, 0});
	state.add_item(Item<int>{&rule, 1});

	EXPECT_TRUE(state.contains(Item<int>{&rule, 0}));
	EXPECT_TRUE(state.contains(Item<int>{&rule, 1}));
	EXPECT_FALSE(state.contains(Item<int>{&rule, 2}));
}

TEST_F(TestState,
Equality) {
	Symbol<int> s1(1, SymbolKind::Nonterminal, "1");
	Symbol<int> s2(2, SymbolKind::Nonterminal, "2");
	Symbol<int> s3(3, SymbolKind::End, "3");
	Rule<int> rule(43, &s1, std::vector<const Symbol<int>*>{&s2, &s3}, [](std::vector<int>&&) -> int { return 0; });

	State<int> state1(1);
	state1.add_item(Item<int>{&rule, 0});
	state1.add_item(Item<int>{&rule, 1});

	State<int> state2(2);
	state2.add_item(Item<int>{&rule, 0});
	state2.add_item(Item<int>{&rule, 1});

	State<int> state3(3);
	state3.add_item(Item<int>{&rule, 0});
	state3.add_item(Item<int>{&rule, 2});

	EXPECT_TRUE(state1 == state2);
	EXPECT_FALSE(state1 == state3);

	EXPECT_FALSE(state1 != state2);
	EXPECT_TRUE(state1 != state3);
}
