/**
 * @file src/types/literal.h
 * @brief Declaration of class Literal.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

#include <string>

namespace yaramod {

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
	///< Type of the literal.
	enum class Type
	{
		String,
		Int,
		Bool
	};

	/// @name Costructors
	/// @{
	Literal() = default;
	explicit Literal(const std::string& value, Literal::Type type);
	explicit Literal(std::string&& value, Literal::Type type);
	explicit Literal(bool boolValue);
	Literal(Literal&& literal) = default;
	Literal(const Literal& literal) = default;
	Literal& operator=(Literal&& literal) = default;
	/// @}

	/// @name String representation
	/// @{
	std::string getText() const;
	std::string getPureText() const;
	/// @}

	/// @name Detection methods
	/// @{
	bool isString() const;
	bool isInt() const;
	bool isBool() const;
	/// @}

private:
	Type _type; ///< Type of literal
	std::string _value; ///< Value used for string and integral literals
	bool _boolValue; ///< Value used for boolean literals
};

}
