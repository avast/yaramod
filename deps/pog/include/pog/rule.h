#pragma once

#include <functional>
#include <string>
#include <vector>

#include <fmt/format.h>
#include <fmt/ostream.h>

#include <pog/symbol.h>
#include <pog/token.h>

namespace pog {

template <typename ValueT>
class Rule
{
public:
	using SymbolType = Symbol<ValueT>;
	using CallbackType = std::function<ValueT(std::vector<ValueT>&&)>;

	Rule(std::uint32_t index, const SymbolType* lhs, const std::vector<const SymbolType*>& rhs)
		: _index(index), _lhs(lhs), _rhs(rhs), _action() {}

	template <typename CallbackT>
	Rule(std::uint32_t index, const SymbolType* lhs, const std::vector<const SymbolType*>& rhs, CallbackT&& action)
		: _index(index), _lhs(lhs), _rhs(rhs), _action(std::forward<CallbackT>(action)) {}

	std::uint32_t get_index() const { return _index; }
	const SymbolType* get_lhs() const { return _lhs; }
	const std::vector<const SymbolType*>& get_rhs() const { return _rhs; }

	bool has_precedence() const { return static_cast<bool>(_precedence); }
	const Precedence& get_precedence() const { return _precedence.value(); }
	void set_precedence(std::uint32_t level, Associativity assoc) { _precedence = Precedence{level, assoc}; }

	const SymbolType* get_rightmost_terminal() const
	{
		auto itr = std::find_if(_rhs.rbegin(), _rhs.rend(), [](const auto& symbol) {
			return symbol->is_terminal();
		});

		return itr != _rhs.rend() ? *itr : nullptr;
	}

	std::string to_string(std::string_view arrow = "->", std::string_view eps = "<eps>") const
	{
		std::vector<std::string> rhs_strings(_rhs.size());
		std::transform(_rhs.begin(), _rhs.end(), rhs_strings.begin(), [](const SymbolType* s) {
			return s->get_name();
		});

		if (rhs_strings.empty())
			rhs_strings.push_back(std::string{eps});

		return fmt::format("{} {} {}", _lhs->get_name(), arrow, fmt::join(rhs_strings.begin(), rhs_strings.end(), " "));
	}

	bool has_action() const { return static_cast<bool>(_action); }

	template <typename... Args>
	ValueT perform_action(Args&&... args) const { return _action(std::forward<Args>(args)...); }

	bool operator==(const Rule& rhs) const { return _index == rhs._index; }
	bool operator!=(const Rule& rhs) const { return !(*this == rhs); }

private:
	std::uint32_t _index;
	const SymbolType* _lhs;
	std::vector<const SymbolType*> _rhs;
	CallbackType _action;
	std::optional<Precedence> _precedence;
};

} // namespace pog
