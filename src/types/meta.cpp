/**
 * @file src/types/meta.cpp
 * @brief Implementation of class Meta.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "yaramod/types/meta.h"

namespace yaramod {

/**
 * Constructor.
 *
 * @param key Key.
 * @param value Value.
 */
Meta::Meta(const std::string& key, Literal&& value) : _key(key), _value(std::move(value))
{
}

/**
 * Constructor.
 *
 * @param key Key.
 * @param value Value.
 */
Meta::Meta(std::string&& key, Literal&& value) : _key(std::move(key)), _value(std::move(value))
{
}

/**
 * Returns the string representation of the meta information.
 *
 * @return String representation.
 */
std::string Meta::getText() const
{
	return getKey() + " = " + getValue().getText();
}

/**
 * Returns the key of a single meta information.
 *
 * @return Key.
 */
const std::string& Meta::getKey() const
{
	return _key;
}

/**
 * Returns the value of a single meta information.
 *
 * @return Value.
 */
const Literal& Meta::getValue() const
{
	return _value;
}

}
