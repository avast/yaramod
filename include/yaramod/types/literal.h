/**
 * @file src/types/literal.h
 * @brief Declaration of class Literal.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

#include <cassert>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <sstream>
#include <variant>

#include "yaramod/yaramod_error.h"

namespace yaramod {

class Symbol;

/**
 * Class representing literal. Literal can be either
 * string, integer or boolean. This class can only bear
 * one literal type at the same time. Behavior is undefined
 * when other type than actual type of the literal is requested.
 *
 * Caution: Integral literals are stored as string to preserve base
 * and all preceding zeroes.
 */
class Literal
{
public:
	/// @name Costructors
	/// @{
	Literal() { assert(is<std::string>()); };
	explicit Literal(const char* value, const std::optional<std::string>& formated_value = std::nullopt);
	explicit Literal(const std::string& value, const std::optional<std::string>& formated_value = std::nullopt);
	explicit Literal(std::string&& value, const std::optional<std::string>& formated_value = std::nullopt);
	explicit Literal(bool boolValue, const std::optional<std::string>& formated_value = std::nullopt);
	explicit Literal(std::int64_t value, const std::optional<std::string>& integral_formatted_value = std::nullopt);
	explicit Literal(std::uint64_t value, const std::optional<std::string>& integral_formatted_value = std::nullopt);
	explicit Literal(double value, const std::optional<std::string>& integral_formatted_value = std::nullopt);
	explicit Literal(const std::shared_ptr<Symbol>& value, const std::string& name);
	explicit Literal(std::shared_ptr<Symbol>&& value, const std::string& name);

	Literal(Literal&& literal) = default;
	Literal(const Literal& literal) = default;
	Literal& operator=(Literal&& literal) = default;
	Literal& operator=(const Literal& literal) = default;
	/// @}

	/// @name Detection methods
	/// @{
	bool isString() const { return is<std::string>(); }
	bool isBool() const { return is<bool>(); }
	bool isInt() const { return is<std::int64_t>() || is<std::uint64_t>(); }
	bool isFloat() const { return is<double>(); }
	bool isSymbol() const { return is<std::shared_ptr<Symbol>>(); }
	/// @}

	/// @name Getter methods
	/// @{
	const std::string& getString() const { return std::get<std::string>(_value); }
	bool getBool() const { return std::get<bool>(_value); }
	std::int64_t getInt() const { return is<std::int64_t>() ? std::get<std::int64_t>(_value) : std::get<std::uint64_t>(_value); }
	std::uint64_t getUInt() const { return is<std::uint64_t>() ? std::get<std::uint64_t>(_value) : std::get<std::int64_t>(_value); }
	double getFloat() const { return std::get<double>(_value); }
	const std::shared_ptr<Symbol>& getSymbol() const { return std::get<std::shared_ptr<Symbol>>(_value); }
	std::string getFormattedValue() const;
	/// @}

	/// @name Setter methods
	/// @{
	void setValue(const std::string& s);
	void setValue(std::string&& s);
	void setValue(bool b);
	void setValue(std::int64_t i, const std::optional<std::string>& integral_formatted_value = std::nullopt);
	void setValue(std::uint64_t i, const std::optional<std::string>& integral_formatted_value = std::nullopt);
	void setValue(double f, const std::optional<std::string>& integral_formatted_value = std::nullopt);
	void setValue(const std::shared_ptr<Symbol>& s, const std::string& symbol_name);
	void setValue(std::shared_ptr<Symbol>&& s, std::string&& symbol_name);
	/// @}

	/// @name String representation
	/// @{
	void markEscaped() {  _escaped = true; }
	std::string getText(bool pure = false) const;
	std::string getPureText() const;
	/// @}

	friend std::ostream& operator<<(std::ostream& os, const Literal& literal)
	{
		if (literal._formatted_value.has_value())
			os << literal._formatted_value.value();
		else if (literal.isBool())
			os << (literal.getBool() ? "true" : "false");
		else
			std::visit(
				[&os](auto&& v)
				{
					os << v;
				},
				literal._value
			);
		return os;
	}

private:
	template <typename T>
	bool is() const { return std::holds_alternative<T>(_value); }

	bool _escaped = false;
	/// For an integral literal x there are two options:
	/// i.  x it is unformatted: _formatted_value is empty  AND  _value contains x
	/// ii. x it is formatted:   _formatted_value contains x's string representation  AND  _value contains pure x
	std::variant<std::string, bool, std::int64_t, std::uint64_t, double, std::shared_ptr<Symbol>> _value; ///< Value used for all literals:
	std::optional<std::string> _formatted_value; ///< Value used for integral literals with particular formatting
};

} //namespace yaramod
