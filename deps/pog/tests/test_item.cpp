#include <gtest/gtest.h>

#include <pog/item.h>

using namespace pog;

class TestItem : public ::testing::Test {};

TEST_F(TestItem,
SimpleItem) {
	Symbol<int> s1(1, SymbolKind::Nonterminal, "1");
	Symbol<int> s2(2, SymbolKind::Nonterminal, "2");
	Symbol<int> s3(3, SymbolKind::Nonterminal, "3");
	Rule<int> rule(42, &s1, std::vector<const Symbol<int>*>{&s2, &s3}, [](std::vector<int>&&) -> int { return 0; });
	Item<int> item(&rule);

	EXPECT_EQ(item.get_rule(), &rule);
	EXPECT_EQ(item.get_read_pos(), 0u);
	EXPECT_EQ(item.get_previous_symbol(), nullptr);
	EXPECT_EQ(item.get_read_symbol(), &s2);

	EXPECT_FALSE(item.is_kernel());
	EXPECT_FALSE(item.is_final());
	EXPECT_FALSE(item.is_accepting());
}

TEST_F(TestItem,
SimpleItemWithReadPosShifted) {
	Symbol<int> s1(1, SymbolKind::Nonterminal, "1");
	Symbol<int> s2(2, SymbolKind::Nonterminal, "2");
	Symbol<int> s3(3, SymbolKind::Nonterminal, "3");
	Rule<int> rule(42, &s1, std::vector<const Symbol<int>*>{&s2, &s3}, [](std::vector<int>&&) -> int { return 0; });
	Item<int> item(&rule, 1);

	EXPECT_EQ(item.get_rule(), &rule);
	EXPECT_EQ(item.get_read_pos(), 1u);
	EXPECT_EQ(item.get_previous_symbol(), &s2);
	EXPECT_EQ(item.get_read_symbol(), &s3);

	EXPECT_TRUE(item.is_kernel());
	EXPECT_FALSE(item.is_final());
	EXPECT_FALSE(item.is_accepting());
}

TEST_F(TestItem,
SimpleItemWithReadPosAtTheEnd) {
	Symbol<int> s1(1, SymbolKind::Nonterminal, "1");
	Symbol<int> s2(2, SymbolKind::Nonterminal, "2");
	Symbol<int> s3(3, SymbolKind::Nonterminal, "3");
	Rule<int> rule(42, &s1, std::vector<const Symbol<int>*>{&s2, &s3}, [](std::vector<int>&&) -> int { return 0; });
	Item<int> item(&rule, 2);

	EXPECT_EQ(item.get_rule(), &rule);
	EXPECT_EQ(item.get_read_pos(), 2u);
	EXPECT_EQ(item.get_previous_symbol(), &s3);
	EXPECT_EQ(item.get_read_symbol(), nullptr);

	EXPECT_TRUE(item.is_kernel());
	EXPECT_TRUE(item.is_final());
	EXPECT_FALSE(item.is_accepting());
}

TEST_F(TestItem,
SimpleAcceptingItem) {
	Symbol<int> s1(1, SymbolKind::Nonterminal, "1");
	Symbol<int> s2(2, SymbolKind::Nonterminal, "2");
	Symbol<int> s3(3, SymbolKind::End, "3");
	Rule<int> rule(42, &s1, std::vector<const Symbol<int>*>{&s2, &s3}, [](std::vector<int>&&) -> int { return 0; });
	Item<int> item(&rule, 1);

	EXPECT_EQ(item.get_rule(), &rule);
	EXPECT_EQ(item.get_read_pos(), 1u);
	EXPECT_EQ(item.get_previous_symbol(), &s2);
	EXPECT_EQ(item.get_read_symbol(), &s3);

	EXPECT_TRUE(item.is_kernel());
	EXPECT_FALSE(item.is_final());
	EXPECT_TRUE(item.is_accepting());
}

TEST_F(TestItem,
LeftSideWithoutReadSymbol) {
	Symbol<int> s1(1, SymbolKind::Nonterminal, "1");
	Symbol<int> s2(2, SymbolKind::Nonterminal, "2");
	Symbol<int> s3(3, SymbolKind::Nonterminal, "3");
	Rule<int> rule(42, &s1, std::vector<const Symbol<int>*>{&s2, &s3}, [](std::vector<int>&&) -> int { return 0; });
	Item<int> item(&rule, 1);

	EXPECT_EQ(item.get_left_side_without_read_symbol(), std::vector<const Symbol<int>*>{&s2});
}

TEST_F(TestItem,
LeftSideWithoutReadSymbolWhenReadPosAtStart) {
	Symbol<int> s1(1, SymbolKind::Nonterminal, "1");
	Symbol<int> s2(2, SymbolKind::Nonterminal, "2");
	Symbol<int> s3(3, SymbolKind::Nonterminal, "3");
	Rule<int> rule(42, &s1, std::vector<const Symbol<int>*>{&s2, &s3}, [](std::vector<int>&&) -> int { return 0; });
	Item<int> item(&rule, 0);

	EXPECT_EQ(item.get_left_side_without_read_symbol(), std::vector<const Symbol<int>*>{});
}

TEST_F(TestItem,
RightSideWithoutReadSymbol) {
	Symbol<int> s1(1, SymbolKind::Nonterminal, "1");
	Symbol<int> s2(2, SymbolKind::Nonterminal, "2");
	Symbol<int> s3(3, SymbolKind::Nonterminal, "3");
	Rule<int> rule(42, &s1, std::vector<const Symbol<int>*>{&s2, &s3}, [](std::vector<int>&&) -> int { return 0; });
	Item<int> item(&rule, 0);

	EXPECT_EQ(item.get_right_side_without_read_symbol(), std::vector<const Symbol<int>*>{&s3});
}

TEST_F(TestItem,
RightSideWithoutReadSymbolWhenNothingIsReturned) {
	Symbol<int> s1(1, SymbolKind::Nonterminal, "1");
	Symbol<int> s2(2, SymbolKind::Nonterminal, "2");
	Symbol<int> s3(3, SymbolKind::Nonterminal, "3");
	Rule<int> rule(42, &s1, std::vector<const Symbol<int>*>{&s2, &s3}, [](std::vector<int>&&) -> int { return 0; });
	Item<int> item(&rule, 1);

	EXPECT_EQ(item.get_right_side_without_read_symbol(), std::vector<const Symbol<int>*>{});
}

TEST_F(TestItem,
Step) {
	Symbol<int> s1(1, SymbolKind::Nonterminal, "1");
	Symbol<int> s2(2, SymbolKind::Nonterminal, "2");
	Symbol<int> s3(3, SymbolKind::Nonterminal, "3");
	Rule<int> rule(42, &s1, std::vector<const Symbol<int>*>{&s2, &s3}, [](std::vector<int>&&) -> int { return 0; });
	Item<int> item(&rule, 0);

	item.step();
	EXPECT_EQ(item.get_read_pos(), 1u);
	item.step();
	EXPECT_EQ(item.get_read_pos(), 2u);
	item.step();
	EXPECT_EQ(item.get_read_pos(), 2u);
}

TEST_F(TestItem,
StepBack) {
	Symbol<int> s1(1, SymbolKind::Nonterminal, "1");
	Symbol<int> s2(2, SymbolKind::Nonterminal, "2");
	Symbol<int> s3(3, SymbolKind::Nonterminal, "3");
	Rule<int> rule(42, &s1, std::vector<const Symbol<int>*>{&s2, &s3}, [](std::vector<int>&&) -> int { return 0; });
	Item<int> item(&rule, 2);

	item.step_back();
	EXPECT_EQ(item.get_read_pos(), 1u);
	item.step_back();
	EXPECT_EQ(item.get_read_pos(), 0u);
	item.step_back();
	EXPECT_EQ(item.get_read_pos(), 0u);
}

TEST_F(TestItem,
ToString) {
	Symbol<int> s1(1, SymbolKind::Nonterminal, "1");
	Symbol<int> s2(2, SymbolKind::Nonterminal, "2");
	Symbol<int> s3(3, SymbolKind::Nonterminal, "3");
	Rule<int> rule(42, &s1, std::vector<const Symbol<int>*>{&s2, &s3}, [](std::vector<int>&&) -> int { return 0; });
	Item<int> item(&rule, 1);

	EXPECT_EQ(item.to_string(), "1 -> 2 <*> 3");
}

TEST_F(TestItem,
EpsilonToString) {
	Symbol<int> s1(1, SymbolKind::Nonterminal, "1");
	Rule<int> rule(42, &s1, std::vector<const Symbol<int>*>{}, [](std::vector<int>&&) -> int { return 0; });
	Item<int> item(&rule, 0);

	EXPECT_EQ(item.to_string(), "1 -> <*> <eps>");
}

TEST_F(TestItem,
Equality) {
	Symbol<int> s1(1, SymbolKind::Nonterminal, "1");
	Symbol<int> s2(2, SymbolKind::Nonterminal, "2");
	Symbol<int> s3(3, SymbolKind::Nonterminal, "3");
	Rule<int> rule1(42, &s1, std::vector<const Symbol<int>*>{&s2, &s3}, [](std::vector<int>&&) -> int { return 0; });
	Rule<int> rule2(42, &s1, std::vector<const Symbol<int>*>{&s2}, [](std::vector<int>&&) -> int { return 0; });
	Rule<int> rule3(43, &s1, std::vector<const Symbol<int>*>{&s2, &s3}, [](std::vector<int>&&) -> int { return 0; });
	Item<int> item1(&rule1, 1);
	Item<int> item2(&rule2, 1);
	Item<int> item3(&rule3, 1);

	EXPECT_TRUE(item1 == item2);
	EXPECT_FALSE(item1 == item3);

	EXPECT_FALSE(item1 != item2);
	EXPECT_TRUE(item1 != item3);

	item1.step();
	EXPECT_FALSE(item1 == item2);
}

TEST_F(TestItem,
LessThanDifferentRule) {
	Symbol<int> s1(1, SymbolKind::Nonterminal, "1");
	Symbol<int> s2(2, SymbolKind::Nonterminal, "2");
	Symbol<int> s3(3, SymbolKind::Nonterminal, "3");
	Rule<int> rule1(42, &s1, std::vector<const Symbol<int>*>{&s2, &s3}, [](std::vector<int>&&) -> int { return 0; });
	Rule<int> rule2(41, &s1, std::vector<const Symbol<int>*>{&s2}, [](std::vector<int>&&) -> int { return 0; });
	Item<int> item1(&rule1, 0);
	Item<int> item2(&rule2, 0);

	EXPECT_FALSE(item1 < item2);
}

TEST_F(TestItem,
LessThanDifferentReadPos) {
	Symbol<int> s1(1, SymbolKind::Nonterminal, "1");
	Symbol<int> s2(2, SymbolKind::Nonterminal, "2");
	Symbol<int> s3(3, SymbolKind::Nonterminal, "3");
	Rule<int> rule1(42, &s1, std::vector<const Symbol<int>*>{&s2, &s3}, [](std::vector<int>&&) -> int { return 0; });
	Rule<int> rule2(42, &s1, std::vector<const Symbol<int>*>{&s2}, [](std::vector<int>&&) -> int { return 0; });
	Item<int> item1(&rule1, 0);
	Item<int> item2(&rule2, 1);

	EXPECT_FALSE(item1 < item2);
}

TEST_F(TestItem,
LessThanWithKernelItemPriority) {
	Symbol<int> s1(1, SymbolKind::Nonterminal, "1");
	Symbol<int> s2(2, SymbolKind::Nonterminal, "2");
	Symbol<int> s3(3, SymbolKind::Nonterminal, "3");
	Rule<int> rule1(42, &s1, std::vector<const Symbol<int>*>{&s2, &s3}, [](std::vector<int>&&) -> int { return 0; });
	Rule<int> rule2(41, &s1, std::vector<const Symbol<int>*>{&s2}, [](std::vector<int>&&) -> int { return 0; });
	Item<int> item1(&rule1, 1);
	Item<int> item2(&rule2, 0);

	EXPECT_TRUE(item1 < item2);
}
