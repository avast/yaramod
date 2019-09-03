#include <cctype>

#include <gtest/gtest.h>

#include <pog/automaton.h>

using namespace pog;

class TestAutomaton : public ::testing::Test
{
public:
	using SetupGrammarTuple = std::tuple<std::string, SymbolKind>;

	TestAutomaton() : grammar() {}

	template <typename... Args>
	State<int> new_state(const Args&... args)
	{
		State<int> state;
		_new_state(state, args...);
		return state;
	}

	void _new_state(State<int>& state, const std::string& lhs, const std::vector<std::string>& left_rhs, const std::vector<std::string>& right_rhs)
	{
		_add_item_to_state(state, lhs, left_rhs, right_rhs);
	}

	template <typename... Args>
	void _new_state(State<int>& state, const std::string& lhs, const std::vector<std::string>& left_rhs, const std::vector<std::string>& right_rhs, const Args&... args)
	{
		_add_item_to_state(state, lhs, left_rhs, right_rhs);
		_new_state(state, args...);
	}

	void _add_item_to_state(State<int>& state, const std::string& lhs, const std::vector<std::string>& left_rhs, const std::vector<std::string>& right_rhs)
	{
		auto lhs_sym = grammar.add_symbol(SymbolKind::Nonterminal, lhs);
		auto sym_transform = [this](const auto& name) {
			return grammar.add_symbol(std::islower(name[0]) ? SymbolKind::Terminal : SymbolKind::Nonterminal, name);
		};

		std::vector<const Symbol<int>*> left_rhs_syms(left_rhs.size());
		std::vector<const Symbol<int>*> right_rhs_syms(right_rhs.size());
		std::vector<const Symbol<int>*> rhs_syms(left_rhs.size() + right_rhs.size());

		std::transform(left_rhs.begin(), left_rhs.end(), left_rhs_syms.begin(), sym_transform);
		std::transform(right_rhs.begin(), right_rhs.end(), right_rhs_syms.begin(), sym_transform);
		std::copy(left_rhs_syms.begin(), left_rhs_syms.end(), rhs_syms.begin());
		std::copy(right_rhs_syms.begin(), right_rhs_syms.end(), rhs_syms.begin() + left_rhs.size());

		Rule<int>* rule = nullptr;
		for (auto& r : grammar.get_rules())
		{
			bool rhs_equal = std::equal(r->get_rhs().begin(), r->get_rhs().end(), rhs_syms.begin(), rhs_syms.end(), [](const auto* sym1, const auto* sym2) {
				return sym1->get_index() == sym2->get_index();
			});
			if (r->get_lhs() == lhs_sym && rhs_equal)
			{
				rule = r.get();
				break;
			}
		}

		if (!rule)
			rule = grammar.add_rule(lhs_sym, rhs_syms, [](auto&&) -> int { return 0; });

		state.add_item(Item<int>{rule, left_rhs.size()});
	}

	Grammar<int> grammar;
};

TEST_F(TestAutomaton,
AddState) {
	auto state = new_state(
		"S", std::vector<std::string>{}, std::vector<std::string>{"a", "S", "b"},
		"S", std::vector<std::string>{}, std::vector<std::string>{}
	);

	Automaton<int> a(&grammar);
	auto result = a.add_state(std::move(state));

	EXPECT_TRUE(result.second);
	EXPECT_EQ(result.first->to_string(), "S -> <*> a S b\nS -> <*> <eps>");
}

TEST_F(TestAutomaton,
AddStateUnique) {
	auto state1 = new_state(
		"S", std::vector<std::string>{}, std::vector<std::string>{"a", "S", "b"},
		"S", std::vector<std::string>{}, std::vector<std::string>{}
	);
	auto state2 = new_state(
		"S", std::vector<std::string>{"a"}, std::vector<std::string>{"S", "b"}
	);

	Automaton<int> a(&grammar);
	auto result1 = a.add_state(std::move(state1));
	auto result2 = a.add_state(std::move(state2));

	EXPECT_TRUE(result1.second);
	EXPECT_EQ(result1.first->to_string(), "S -> <*> a S b\nS -> <*> <eps>");
	EXPECT_TRUE(result2.second);
	EXPECT_EQ(result2.first->to_string(), "S -> a <*> S b");
}

TEST_F(TestAutomaton,
AddStateDuplicate) {
	auto state1 = new_state(
		"S", std::vector<std::string>{}, std::vector<std::string>{"a", "S", "b"},
		"S", std::vector<std::string>{}, std::vector<std::string>{}
	);
	auto state2 = new_state(
		"S", std::vector<std::string>{}, std::vector<std::string>{"a", "S", "b"},
		"S", std::vector<std::string>{}, std::vector<std::string>{}
	);

	Automaton<int> a(&grammar);
	auto result1 = a.add_state(std::move(state1));
	auto result2 = a.add_state(std::move(state2));

	EXPECT_TRUE(result1.second);
	EXPECT_EQ(result1.first->to_string(), "S -> <*> a S b\nS -> <*> <eps>");
	EXPECT_FALSE(result2.second);
	EXPECT_EQ(result1.first, result2.first);
}

TEST_F(TestAutomaton,
GetState) {
	auto state = new_state(
		"S", std::vector<std::string>{}, std::vector<std::string>{"a", "S", "b"},
		"S", std::vector<std::string>{}, std::vector<std::string>{}
	);

	Automaton<int> a(&grammar);
	a.add_state(std::move(state));

	state = new_state(
		"S", std::vector<std::string>{}, std::vector<std::string>{"a", "S", "b"},
		"S", std::vector<std::string>{}, std::vector<std::string>{}
	);

	EXPECT_EQ(*a.get_state(0), state);
}

TEST_F(TestAutomaton,
Closure) {
	auto state = new_state(
		"S", std::vector<std::string>{"A"}, std::vector<std::string>{"S", "b"}
	);
	new_state(
		"A", std::vector<std::string>{"a"}, std::vector<std::string>{"A"},
		"A", std::vector<std::string>{}, std::vector<std::string>{}
	);

	Automaton<int> a(&grammar);
	a.closure(state);

	EXPECT_EQ(state.to_string(), "S -> A <*> S b\nS -> <*> A S b\nA -> <*> a A\nA -> <*> <eps>");
}

TEST_F(TestAutomaton,
ConstructStates) {
	grammar.set_start_symbol(grammar.add_symbol(SymbolKind::Nonterminal, "S"));
	new_state(
		"S", std::vector<std::string>{}, std::vector<std::string>{"a", "S", "b"},
		"S", std::vector<std::string>{}, std::vector<std::string>{}
	);

	Automaton<int> a(&grammar);
	a.construct_states();

	EXPECT_EQ(a.get_states().size(), 5u);
	EXPECT_EQ(a.get_states()[0]->to_string(), "@start -> <*> S @end\nS -> <*> a S b\nS -> <*> <eps>");
	EXPECT_EQ(a.get_states()[1]->to_string(), "@start -> S <*> @end");
	EXPECT_EQ(a.get_states()[2]->to_string(), "S -> a <*> S b\nS -> <*> a S b\nS -> <*> <eps>");
	EXPECT_EQ(a.get_states()[3]->to_string(), "S -> a S <*> b");
	EXPECT_EQ(a.get_states()[4]->to_string(), "S -> a S b <*>");
}
