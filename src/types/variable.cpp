/**
 * @file src/types/variable.cpp
 * @brief Implementation of class Variable.
 * @copyright (c) 2020 Avast Software, licensed under the MIT license
 */

#include "yaramod/types/variable.h"
#include "yaramod/types/expression.h"

namespace yaramod {

/**
 * Returns the string representation of variable.
 *
 * @return String representation.
 */
std::string Variable::getText() const
{
	return getKey() + " = " + getValue()->getText();
}

/**
 * Returns the key of a variable.
 *
 * @return Key.
 */
const std::string& Variable::getKey() const
{
	return _key->getString();
}

/**
 * Returns the token iterator of the key of a variable.
 *
 * @return Key.
 */
TokenIt Variable::getKeyTokenIt() const
{
	return _key;
}

/**
 * Returns the value of a variable.
 *
 * @return Value.
 */
const Expression::Ptr& Variable::getValue() const
{
	return std::move(_value);
}

/**
 * Set the key of a variable.
 *
 * @param key Key.
 */
void Variable::setKey(const std::string& key)
{
	_key->setValue(key);
}

/**
 * Sets the value of a variable.
 *
 * @param value Value.
 */
void Variable::setValue(const Expression::Ptr& value)
{
	_value = std::move(value);
}

}
