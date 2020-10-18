/**
 * @file src/types/variable.h
 * @brief Declaration of class Variable.
 * @copyright (c) 2020 Avast Software, licensed under the MIT license
 */

#pragma once

#include <string>

#include "yaramod/types/token.h"
#include "yaramod/types/expression.h"

namespace yaramod {

/**
 * Class representing variable
 * in the YARA rules.
 */
class Variable
{
public:
	/// @name Constructors
	/// @{
	Variable(TokenIt& key, Expression::Ptr value) : _key(key), _value(value) {}
	Variable(const Variable& variable) = default;
	Variable(Variable&& variable) = default;
	/// @}

	/// @name Assignment
	/// @{
	Variable& operator=(const Variable&) = default;
	Variable& operator=(Variable&&) = default;
	/// @}

	/// @name String representation
	/// @{
	std::string getText() const;
	/// @}

	/// @name Getter methods
	/// @{
	const std::string& getKey() const;
	TokenIt getKeyTokenIt() const;
	const Expression::Ptr& getValue() const;
	/// @}

	/// @name Setter methods
	/// @{
	void setKey(const std::string& key);
	void setValue(const Expression::Ptr& value);
	/// @}

private:
	TokenIt _key; ///< Key
	Expression::Ptr _value; ///< Value
};

}
