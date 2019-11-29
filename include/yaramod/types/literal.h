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
	explicit Literal(int value, const std::optional<std::string>& integral_formated_value = std::nullopt);
	explicit Literal(int64_t value, const std::optional<std::string>& integral_formated_value = std::nullopt);
	explicit Literal(uint64_t value, const std::optional<std::string>& integral_formated_value = std::nullopt);
	explicit Literal(double value, const std::optional<std::string>& integral_formated_value = std::nullopt);
	explicit Literal(const std::shared_ptr<Symbol>& value, const std::string& name);
	explicit Literal(std::shared_ptr<Symbol>&& value, const std::string& name);

	Literal(Literal&& literal) = default;
	Literal(const Literal& literal) = default;
	Literal& operator=(Literal&& literal) = default;
	Literal& operator=(const Literal& literal) = default;
	/// @}

	/// @name Setter methods
	/// @{
	void setValue(const std::string& s);
	void setValue(std::string&& s);
	void setValue(bool b);
	void setValue(int i, const std::optional<std::string>& integral_formated_value = std::nullopt);
	void setValue(int64_t i, const std::optional<std::string>& integral_formated_value = std::nullopt);
	void setValue(uint64_t i, const std::optional<std::string>& integral_formated_value = std::nullopt);
	void setValue(double f, const std::optional<std::string>& integral_formated_value = std::nullopt);
	void setValue(const std::shared_ptr<Symbol>& s, const std::string& symbol_name);
	void setValue(std::shared_ptr<Symbol>&& s, std::string&& symbol_name);

	void markEscaped() {  _escaped = true; }
	/// @}

	/// @name Getter methods
	/// @{
	template <typename T>
	const T& get() const
	{
		try
		{
			return std::get<T>(_value);
		}
		catch (std::bad_variant_access& exp)
		{
			std::stringstream err;
			err << "Called get() of a TokenValue, which holds '" << *this << "'. Actual variant index is " << _value.index() << "." << std::endl << exp.what() << std::endl;
			throw YaramodError(err.str());
		}
	}

	template <typename T>
	const T& getValue() const
	{
		try
		{
			return std::get<T>(_value);
		}
		catch (std::bad_variant_access& exp)
		{
			std::stringstream ss;
			ss << "Error: Called getValue<T>() with incompatible type T. The Literal value contains '" << *this << "'. Actual variant index is " << _value.index() << "." << std::endl << exp.what() << std::endl;
			throw YaramodError(ss.str());
		}
	}

	std::string getFormattedValue() const;
	/// @}

	/// @name String representation
	/// @{
	std::string getText(bool pure = false) const;
	std::string getPureText() const;
	/// @}

	/// @name Detection methods
	/// @{
	template <typename T>
	bool is() const { return std::holds_alternative<T>(_value); }
	bool isIntegral() const;
	/// @}

	friend std::ostream& operator<<(std::ostream& os, const Literal& literal)
	{
		if (literal._formated_value.has_value())
			os << literal._formated_value.value();
		else if (literal.is<bool>()){
			os << (literal.get<bool>() ? "true" : "false");
		}
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
	bool _escaped = false;
	/// For an integral literal x there are two options:
	/// i.  x it is unformatted:	_formated_value is empty  AND  _value contains x
	/// ii. x it is formatted:	  _formated_value contains x's string representation  AND  _value contains pure x
	std::variant<std::string, bool, int, int64_t, uint64_t, double, std::shared_ptr<Symbol>> _value; ///< Value used for all literals:
	std::optional<std::string> _formated_value; ///< Value used for integral literals with particular formatting
};

} //namespace yaramod
