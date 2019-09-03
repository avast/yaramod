#pragma once

#include <pog/grammar.h>
#include <pog/rule.h>

namespace pog {

template <typename ValueT>
class RuleBuilder
{
public:
	using GrammarType = Grammar<ValueT>;
	using RuleType = Rule<ValueT>;
	using SymbolType = Symbol<ValueT>;

	struct SymbolsAndAction
	{
		std::vector<std::string> symbols;
		typename RuleType::CallbackType action;
	};

	struct RightHandSide
	{
		std::vector<SymbolsAndAction> symbols_and_action;
		std::optional<Precedence> precedence;
	};

	RuleBuilder(GrammarType* grammar, const std::string& lhs) : _grammar(grammar), _lhs(lhs), _rhss() {}

	void done()
	{
		if (_rhss.empty())
			return;

		const auto* lhs_symbol = _grammar->add_symbol(SymbolKind::Nonterminal, _lhs);

		std::size_t rhs_counter = 0;
		for (auto&& rhs : _rhss)
		{
			RuleType* rule = nullptr;

			// There are multple actions (mid-rule actions) so we need to create new symbol and split the rule
			// If you have rule A -> B C D and you want to perform action after B, then we'll create rules
			// A -> A0 A1
			// A0 -> B
			// A1 -> C D
			if (rhs.symbols_and_action.size() > 1)
			{
				std::vector<const SymbolType*> main_rhs_symbols(rhs.symbols_and_action.size());
				for (std::size_t i = 0; i < rhs.symbols_and_action.size(); ++i)
				{
					// Create those main level symbol A_i which will be used as left-hand side of the newly created subrule
					main_rhs_symbols[i] = _grammar->add_symbol(
						SymbolKind::Nonterminal,
						fmt::format("_{}#{}.{}", _lhs, rhs_counter, i)
					);
				}

				// Create main level rule A -> A_1 A_2 .. A_n and pass through result from A_n
				rule = _grammar->add_rule(lhs_symbol, main_rhs_symbols, [](auto&& args) {
					return !args.empty() ? std::move(args.back()) : ValueT{};
				});

				// Create subrule with A_i as left-hand side
				std::size_t counter = 0;
				for (auto&& symbols_and_action : rhs.symbols_and_action)
				{
					std::vector<const SymbolType*> rhs_symbols(symbols_and_action.symbols.size());
					std::transform(symbols_and_action.symbols.begin(), symbols_and_action.symbols.end(), rhs_symbols.begin(), [this](const auto& sym_name) {
						return _grammar->add_symbol(SymbolKind::Nonterminal, sym_name);
					});
					_grammar->add_rule(main_rhs_symbols[counter++], rhs_symbols, std::move(symbols_and_action.action));
				}
			}
			else if (rhs.symbols_and_action.size() == 1)
			{
				std::vector<const SymbolType*> rhs_symbols(rhs.symbols_and_action[0].symbols.size());
				std::transform(rhs.symbols_and_action[0].symbols.begin(), rhs.symbols_and_action[0].symbols.end(), rhs_symbols.begin(), [this](const auto& sym_name) {
					return _grammar->add_symbol(SymbolKind::Nonterminal, sym_name);
				});
				rule = _grammar->add_rule(lhs_symbol, rhs_symbols, std::move(rhs.symbols_and_action[0].action));
			}
			else
				assert(false && "No symbols and action associated to right-hand side of the rule. This shouldn't happen");

			if (rule && rhs.precedence)
			{
				const auto& prec = rhs.precedence.value();
				rule->set_precedence(prec.level, prec.assoc);
			}

			rhs_counter++;
		}
	}

	template <typename... Args>
	RuleBuilder& production(Args&&... args)
	{
		_rhss.push_back(RightHandSide{
			std::vector<SymbolsAndAction>{
				SymbolsAndAction{
					std::vector<std::string>{},
					{}
				}
			},
			std::nullopt
		});
		_production(_rhss.back().symbols_and_action, std::forward<Args>(args)...);
		return *this;
	}

	RuleBuilder& precedence(std::uint32_t level, Associativity assoc)
	{
		_rhss.back().precedence = Precedence{level, assoc};
		return *this;
	}

private:
	void _production(std::vector<SymbolsAndAction>&) {}

	template <typename... Args>
	void _production(std::vector<SymbolsAndAction>& sa, const std::string& symbol, Args&&... args)
	{
		sa.back().symbols.push_back(symbol);
		_production(sa, std::forward<Args>(args)...);
	}

	template <typename... Args>
	void _production(std::vector<SymbolsAndAction>& sa, typename RuleType::CallbackType&& action, Args&&... args)
	{
		sa.back().action = std::move(action);
		// We have ran into action so create new record in symbols and actions vector
		// but only if it isn't the very last thing in the production
		if constexpr (sizeof...(args) > 0)
			sa.push_back(SymbolsAndAction{
				std::vector<std::string>{},
				{}
			});
		_production(sa, std::forward<Args>(args)...);
	}

	GrammarType* _grammar;
	std::string _lhs;
	std::vector<RightHandSide> _rhss;
};

} // namespace pog
