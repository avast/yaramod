/**
 * @file src/types/literal.cpp
 * @brief Implementation of class Literal.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <cassert>
#include <sstream>

#include "yaramod/types/literal.h"
#include "yaramod/utils/utils.h"

namespace yaramod {

/**
 * Constructor.
 *
 * @param value String or integral value of the literal.
 * @param type Type of the literal.
 */
Literal::Literal(const std::string& value, Literal::Type type) : _type(type), _value(value), _boolValue(false)
{
}

/**
 * Constructor.
 *
 * @param value String or integral value of the literal.
 * @param type Type of the literal.
 */
Literal::Literal(std::string&& value, Literal::Type type) : _type(type), _value(std::move(value)), _boolValue(false)
{
}

/**
 * Constructor.
 *
 * @param boolValue Boolean value of the literal.
 */
Literal::Literal(bool boolValue) : _type(Literal::Type::Bool), _value(), _boolValue(boolValue)
{
}

/**
 * Returns the string representation of the literal.
 *
 * @return String representation.
 */
std::string Literal::getText() const
{
	if (isString())
		return '"' + escapeString(_value) + '"';
	else if (isInt())
		return _value;
	else if (isBool())
	{
		std::ostringstream ss;
		ss << std::boolalpha << _boolValue;
		return ss.str();
	}

	return std::string();
}

/**
 * Returns the string representation but string literals are not enclosed in double quotes.
 *
 * @return String representation.
 */
std::string Literal::getPureText() const
{
	if (isString() || isInt())
		return _value;
	else if (isBool())
	{
		std::ostringstream ss;
		ss << std::boolalpha << _boolValue;
		return ss.str();
	}

	return std::string();
}

/**
 * Returns whether the literal is of string type.
 *
 * @return @c true if is of string type, otherwise @c false.
 */
bool Literal::isString() const
{
	return _type == Literal::Type::String;
}

/**
 * Returns whether the literal is of integer type.
 *
 * @return @c true if is of integer type, otherwise @c false.
 */
bool Literal::isInt() const
{
	return _type == Literal::Type::Int;
}

/**
 * Returns whether the literal is of boolean type.
 *
 * @return @c true if is of boolean type, otherwise @c false.
 */
bool Literal::isBool() const
{
	return _type == Literal::Type::Bool;
}

}
