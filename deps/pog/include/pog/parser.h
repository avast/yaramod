#pragma once

#include <deque>
#include <unordered_map>

#include <pog/action.h>
#include <pog/automaton.h>
#include <pog/errors.h>
#include <pog/grammar.h>
#include <pog/parser_report.h>
#include <pog/parsing_table.h>
#include <pog/rule_builder.h>
#include <pog/state.h>
#include <pog/symbol.h>
#include <pog/token_builder.h>
#include <pog/tokenizer.h>

#include <pog/operations/read.h>
#include <pog/operations/follow.h>
#include <pog/operations/lookahead.h>
#include <pog/relations/includes.h>
#include <pog/relations/lookback.h>

namespace pog {

template <typename ValueT>
class HtmlReport;

template <typename ValueT>
class Parser
{
public:
	friend class HtmlReport<ValueT>;

	using ActionType = Action<ValueT>;
	using ShiftActionType = Shift<ValueT>;
	using ReduceActionType = Reduce<ValueT>;

	using BacktrackingInfoType = BacktrackingInfo<ValueT>;
	using ItemType = Item<ValueT>;
	using ParserReportType = ParserReport<ValueT>;
	using RuleBuilderType = RuleBuilder<ValueT>;
	using RuleType = Rule<ValueT>;
	using StateType = State<ValueT>;
	using SymbolType = Symbol<ValueT>;
	using StateAndRuleType = StateAndRule<ValueT>;
	using StateAndSymbolType = StateAndSymbol<ValueT>;
	using TokenBuilderType = TokenBuilder<ValueT>;
	using TokenMatchType = TokenMatch<ValueT>;
	using TokenType = Token<ValueT>;

	Parser() : _grammar(), _tokenizer(&_grammar), _automaton(&_grammar), _includes(&_automaton, &_grammar),
		_lookback(&_automaton, &_grammar), _read_operation(&_automaton, &_grammar), _follow_operation(&_automaton, &_grammar, _includes, _read_operation),
		_lookahead_operation(&_automaton, &_grammar, _lookback, _follow_operation), _parsing_table(&_automaton, &_grammar, _lookahead_operation)
	{
		static_assert(std::is_default_constructible_v<ValueT>, "Value type needs to be default constructible");
	}

	Parser(const Parser<ValueT>&) = delete;
	Parser(Parser<ValueT>&&) noexcept = default;

	const ParserReportType& prepare()
	{
		for (auto& tb : _token_builders)
			tb.done();
		for (auto& rb : _rule_builders)
			rb.done();
		_automaton.construct_states();
		_includes.calculate();
		_lookback.calculate();
		_read_operation.calculate();
		_follow_operation.calculate();
		_lookahead_operation.calculate();
		_parsing_table.calculate(_report);
		_tokenizer.prepare();
		return _report;
	}

	TokenBuilderType& token(const std::string& pattern)
	{
		_token_builders.emplace_back(&_grammar, &_tokenizer, pattern);
		return _token_builders.back();
	}

	TokenBuilderType& end_token()
	{
		_token_builders.emplace_back(&_grammar, &_tokenizer);
		return _token_builders.back();
	}

	RuleBuilderType& rule(const std::string& lhs)
	{
		_rule_builders.emplace_back(&_grammar, lhs);
		return _rule_builders.back();
	}

	void set_start_symbol(const std::string& name)
	{
		_grammar.set_start_symbol(_grammar.add_symbol(SymbolKind::Nonterminal, name));
	}

	void push_input_stream(std::istream& input)
	{
		_tokenizer.push_input_stream(input);
	}

	void pop_input_stream()
	{
		_tokenizer.pop_input_stream();
	}

	std::optional<ValueT> parse(std::istream& input)
	{
		std::optional<TokenMatchType> token;
		_tokenizer.push_input_stream(input);

		std::deque<std::pair<std::uint32_t, std::optional<ValueT>>> stack;
		stack.emplace_back(0, std::nullopt);

		while (!stack.empty())
		{
			// Check if we remember token from the last iteration because we did reduction
			// so the token was not "consumed" from the input.
			if (!token)
			{
				token = _tokenizer.next_token();
				if (!token)
				{
					auto expected_symbols = _parsing_table.get_expected_symbols_from_state(_automaton.get_state(stack.back().first));
					throw SyntaxError(expected_symbols);
				}
			}

			const auto* next_symbol = token.value().symbol;
			auto maybe_action = _parsing_table.get_action(_automaton.get_state(stack.back().first), next_symbol);
			if (!maybe_action)
			{
				auto expected_symbols = _parsing_table.get_expected_symbols_from_state(_automaton.get_state(stack.back().first));
				throw SyntaxError(next_symbol, expected_symbols);
			}

			// TODO: use visit
			auto action = maybe_action.value();
			if (std::holds_alternative<ReduceActionType>(action))
			{
				const auto& reduce = std::get<ReduceActionType>(action);

				// Each symbol on right-hand side of the rule should have record on the stack
				// We'll pop them out and put them in reverse order so user have them available
				// left-to-right and not right-to-left.
				std::vector<ValueT> action_arg;
				action_arg.reserve(reduce.rule->get_rhs().size());
				assert(stack.size() >= reduce.rule->get_rhs().size() && "Stack is too small");

				for (std::size_t i = 0; i < action_arg.capacity(); ++i)
				{
					// Notice how std::move() is only around optional itself and not the whole expressions
					// We need to do this in order to perform move together with value_or()
					// See: https://en.cppreference.com/w/cpp/utility/optional/value_or
					// std::move(*this) is performed only when value_or() is called from r-value
					action_arg.insert(action_arg.begin(), std::move(stack.back().second).value_or(ValueT{}));
					stack.pop_back();
				}

				// What left on the stack now determines what state we get into now
				auto maybe_next_state = _parsing_table.get_transition(_automaton.get_state(stack.back().first), reduce.rule->get_lhs());
				if (!maybe_next_state)
				{
					assert(false && "Reduction happened but corresponding GOTO table record is empty");
					return std::nullopt;
				}

				stack.emplace_back(
					maybe_next_state.value()->get_index(),
					reduce.rule->has_action() ? reduce.rule->perform_action(std::move(action_arg)) : ValueT{}
				);
			}
			else if (std::holds_alternative<ShiftActionType>(action))
			{
				// Notice how std::move() is only around optional itself and not the whole expressions
				// We need to do this in order to perform move together with value()
				// See: https://en.cppreference.com/w/cpp/utility/optional/value
				// Return by rvalue is performed only when value() is called from r-value
				stack.emplace_back(
					std::get<ShiftActionType>(action).state->get_index(),
					std::move(token).value().value
				);

				// We did shift so the token value is moved onto stack, "forget" the token
				token.reset();
			}
			else if (std::holds_alternative<Accept>(action))
			{
				// Notice how std::move() is only around optional itself and not the whole expressions
				// We need to do this in order to perform move together with value()
				// See: https://en.cppreference.com/w/cpp/utility/optional/value
				// Return by rvalue is performed only when value() is called from r-value
				return std::move(stack.back().second).value();
			}
		}

		assert(false && "Stack was emptied too early");
		return std::nullopt;
	}

	std::string generate_automaton_graph()
	{
		return _automaton.generate_graph();
	}

	std::string generate_includes_relation_graph()
	{
		return _includes.generate_relation_graph();
	}

private:
	Grammar<ValueT> _grammar;
	Tokenizer<ValueT> _tokenizer;
	Automaton<ValueT> _automaton;
	Includes<ValueT> _includes;
	Lookback<ValueT> _lookback;
	Read<ValueT> _read_operation;
	Follow<ValueT> _follow_operation;
	Lookahead<ValueT> _lookahead_operation;
	ParsingTable<ValueT> _parsing_table;

	std::vector<RuleBuilderType> _rule_builders;
	std::vector<TokenBuilderType> _token_builders;

	ParserReportType _report;
};

} // namespace pog
