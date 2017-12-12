/**
 * @file src/types/expression.h
 * @brief Declaration of class Expression.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "yaramod/utils/visitee.h"

namespace yaramod {

/**
 * Class representing expression in the condition section
 * of the YARA rule. Expression bears the value of certain type.
 */
class Expression : public Visitee
{
public:
	///< Type of the expression.
	enum class Type
	{
		Undefined,
		Bool,
		Int,
		String,
		Regexp,
		Object,
		Float
	};

	/// @name Constructors
	/// @{
	Expression() : _type(Expression::Type::Undefined) {}
	Expression(Expression&&) = default;
	virtual ~Expression() {}
	/// @}

	/// @name String representation
	/// @{
	virtual std::string getText(const std::string& indent = "") const = 0;
	/// @}

	/// @name Getter methods
	/// @{
	Expression::Type getType() const { return _type; }
	/// @}

	/// @name Setter methods
	/// @{
	void setType(Expression::Type type) { _type = type; }
	/// @}

	/// @name Detection methods
	/// @{
	bool isBool() const { return _type == Expression::Type::Bool; }
	bool isInt() const { return _type == Expression::Type::Int; }
	bool isString() const { return _type == Expression::Type::String; }
	bool isRegexp() const { return _type == Expression::Type::Regexp; }
	bool isObject() const { return _type == Expression::Type::Object; }
	bool isFloat() const { return _type == Expression::Type::Float; }
	/// @}

private:
	Type _type; ///< Type of the expression
};

}
