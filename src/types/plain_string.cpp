/**
 * @file src/types/plain_string.cpp
 * @brief Implementation of class PlainString.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "yaramod/types/plain_string.h"
#include "yaramod/utils/utils.h"

namespace yaramod {

/**
 * Constructor.
 *
 * @param text Text of the plain string.
 */
PlainString::PlainString(const std::string& text) : String(String::Type::Plain), _text(text)
{
}

/**
 * Constructor.
 *
 * @param text Text of the plain string.
 */
PlainString::PlainString(std::string&& text) : String(String::Type::Plain), _text(std::move(text))
{
}

/**
 * Return the string representation of the plain string.
 *
 * @return String representation.
 */
std::string PlainString::getText() const
{
	return '"' + escapeString(getPureText()) + '"' + getModifiersText();
}

/**
 * Return the pure string representation of the plain string.
 *
 * @return Pure string representation.
 */
std::string PlainString::getPureText() const
{
	return _text;
}

}
