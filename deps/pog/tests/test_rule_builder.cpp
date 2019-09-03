#include <gtest/gtest.h>

#include <pog/rule_builder.h>

using namespace pog;

class TestRuleBuilder : public ::testing::Test
{
public:
	Grammar<int> grammar;
};

TEST_F(TestRuleBuilder,
Initialization) {
	RuleBuilder<int> rb(&grammar, "A");

	EXPECT_EQ(grammar.get_symbols().size(), 2u); // start and end symbol
	EXPECT_TRUE(grammar.get_rules().empty());
}

TEST_F(TestRuleBuilder,
NoProductions) {
	RuleBuilder<int> rb(&grammar, "A");
	rb.done();

	EXPECT_EQ(grammar.get_symbols().size(), 2u);
	EXPECT_TRUE(grammar.get_rules().empty());
}

TEST_F(TestRuleBuilder,
SingleProductionWithoutAction) {
	RuleBuilder<int> rb(&grammar, "A");
	rb.production("a");
	rb.done();

	EXPECT_EQ(grammar.get_symbols().size(), 4u);
	EXPECT_EQ(grammar.get_rules().size(), 1u);
	EXPECT_EQ(grammar.get_rules()[0]->to_string(), "A -> a");
	EXPECT_FALSE(grammar.get_rules()[0]->has_action());
}

TEST_F(TestRuleBuilder,
SingleProductionWithAction) {
	RuleBuilder<int> rb(&grammar, "A");
	rb.production("a", [](auto&&) { return 42; });
	rb.done();

	EXPECT_EQ(grammar.get_symbols().size(), 4u);
	EXPECT_EQ(grammar.get_rules().size(), 1u);
	EXPECT_EQ(grammar.get_rules()[0]->to_string(), "A -> a");
	EXPECT_TRUE(grammar.get_rules()[0]->has_action());
}

TEST_F(TestRuleBuilder,
MultipleProductionsWithActions) {
	RuleBuilder<int> rb(&grammar, "A");
	rb.production("A", "a", [](auto&&) { return 42; })
		.production("a", [](auto&&) { return 42; });
	rb.done();

	EXPECT_EQ(grammar.get_symbols().size(), 4u);
	EXPECT_EQ(grammar.get_rules().size(), 2u);
	EXPECT_EQ(grammar.get_rules()[0]->to_string(), "A -> A a");
	EXPECT_EQ(grammar.get_rules()[1]->to_string(), "A -> a");
	EXPECT_TRUE(grammar.get_rules()[0]->has_action());
	EXPECT_TRUE(grammar.get_rules()[1]->has_action());
}

TEST_F(TestRuleBuilder,
SingleProductionWithMidruleActions) {
	RuleBuilder<int> rb(&grammar, "func");
	rb.production(
		"func", "id", [](auto&&) { return 42; },
		"{", "body", "}", [](auto&&) { return 43; }
	);
	rb.done();

	EXPECT_EQ(grammar.get_symbols().size(), 9u);
	EXPECT_EQ(grammar.get_rules().size(), 3u);
	EXPECT_EQ(grammar.get_rules()[0]->to_string(), "func -> _func#0.0 _func#0.1");
	EXPECT_EQ(grammar.get_rules()[1]->to_string(), "_func#0.0 -> func id");
	EXPECT_EQ(grammar.get_rules()[2]->to_string(), "_func#0.1 -> { body }");
	EXPECT_TRUE(grammar.get_rules()[0]->has_action());
	EXPECT_TRUE(grammar.get_rules()[1]->has_action());
	EXPECT_TRUE(grammar.get_rules()[2]->has_action());

	EXPECT_EQ(grammar.get_rules()[0]->perform_action(std::vector<int>{}), 0);
	EXPECT_EQ(grammar.get_rules()[0]->perform_action(std::vector<int>{1, 2, 3}), 3);
	EXPECT_EQ(grammar.get_rules()[1]->perform_action(std::vector<int>{}), 42);
	EXPECT_EQ(grammar.get_rules()[1]->perform_action(std::vector<int>{1, 2, 3}), 42);
	EXPECT_EQ(grammar.get_rules()[2]->perform_action(std::vector<int>{}), 43);
	EXPECT_EQ(grammar.get_rules()[2]->perform_action(std::vector<int>{1, 2, 3}), 43);
}

TEST_F(TestRuleBuilder,
MultipleProductionsWithMidruleActions) {
	RuleBuilder<int> rb(&grammar, "def");
	rb.production(
		"func", "id", [](auto&&) { return 42; },
		"(", "args", ")", [](auto&&) { return 43; },
		"{", "body", "}", [](auto&&) { return 44; }
	)
	.production(
		"var", "id", "=", [](auto&&) { return 142; },
		"expr", [](auto&&) { return 143; }
	);
	rb.done();

	EXPECT_EQ(grammar.get_symbols().size(), 19u);
	EXPECT_EQ(grammar.get_rules().size(), 7u);
	EXPECT_EQ(grammar.get_rules()[0]->to_string(), "def -> _def#0.0 _def#0.1 _def#0.2");
	EXPECT_EQ(grammar.get_rules()[1]->to_string(), "_def#0.0 -> func id");
	EXPECT_EQ(grammar.get_rules()[2]->to_string(), "_def#0.1 -> ( args )");
	EXPECT_EQ(grammar.get_rules()[3]->to_string(), "_def#0.2 -> { body }");
	EXPECT_EQ(grammar.get_rules()[4]->to_string(), "def -> _def#1.0 _def#1.1");
	EXPECT_EQ(grammar.get_rules()[5]->to_string(), "_def#1.0 -> var id =");
	EXPECT_EQ(grammar.get_rules()[6]->to_string(), "_def#1.1 -> expr");
	EXPECT_TRUE(grammar.get_rules()[0]->has_action());
	EXPECT_TRUE(grammar.get_rules()[1]->has_action());
	EXPECT_TRUE(grammar.get_rules()[2]->has_action());
	EXPECT_TRUE(grammar.get_rules()[3]->has_action());
	EXPECT_TRUE(grammar.get_rules()[4]->has_action());
	EXPECT_TRUE(grammar.get_rules()[5]->has_action());
	EXPECT_TRUE(grammar.get_rules()[6]->has_action());

	EXPECT_EQ(grammar.get_rules()[0]->perform_action(std::vector<int>{}), 0);
	EXPECT_EQ(grammar.get_rules()[0]->perform_action(std::vector<int>{1, 2, 3}), 3);
	EXPECT_EQ(grammar.get_rules()[1]->perform_action(std::vector<int>{}), 42);
	EXPECT_EQ(grammar.get_rules()[1]->perform_action(std::vector<int>{1, 2, 3}), 42);
	EXPECT_EQ(grammar.get_rules()[2]->perform_action(std::vector<int>{}), 43);
	EXPECT_EQ(grammar.get_rules()[2]->perform_action(std::vector<int>{1, 2, 3}), 43);
	EXPECT_EQ(grammar.get_rules()[3]->perform_action(std::vector<int>{}), 44);
	EXPECT_EQ(grammar.get_rules()[3]->perform_action(std::vector<int>{1, 2, 3}), 44);
	EXPECT_EQ(grammar.get_rules()[4]->perform_action(std::vector<int>{}), 0);
	EXPECT_EQ(grammar.get_rules()[4]->perform_action(std::vector<int>{1, 2, 3}), 3);
	EXPECT_EQ(grammar.get_rules()[5]->perform_action(std::vector<int>{}), 142);
	EXPECT_EQ(grammar.get_rules()[5]->perform_action(std::vector<int>{1, 2, 3}), 142);
	EXPECT_EQ(grammar.get_rules()[6]->perform_action(std::vector<int>{}), 143);
	EXPECT_EQ(grammar.get_rules()[6]->perform_action(std::vector<int>{1, 2, 3}), 143);
}

TEST_F(TestRuleBuilder,
EpsilonRuleWithAction) {
	RuleBuilder<int> rb(&grammar, "A");
	rb.production("A", "a", [](auto&&) { return 42; })
		.production([](auto&&) { return 43; });
	rb.done();

	EXPECT_EQ(grammar.get_symbols().size(), 4u);
	EXPECT_EQ(grammar.get_rules().size(), 2u);
	EXPECT_EQ(grammar.get_rules()[0]->to_string(), "A -> A a");
	EXPECT_EQ(grammar.get_rules()[1]->to_string(), "A -> <eps>");
	EXPECT_TRUE(grammar.get_rules()[0]->has_action());
	EXPECT_TRUE(grammar.get_rules()[1]->has_action());

	EXPECT_EQ(grammar.get_rules()[0]->perform_action(std::vector<int>{}), 42);
	EXPECT_EQ(grammar.get_rules()[0]->perform_action(std::vector<int>{1, 2, 3}), 42);
	EXPECT_EQ(grammar.get_rules()[1]->perform_action(std::vector<int>{}), 43);
	EXPECT_EQ(grammar.get_rules()[1]->perform_action(std::vector<int>{1, 2, 3}), 43);
}
