/**
 * @file src/types/plain_string.h
 * @brief Declaration of class PlainString.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

#include "yaramod/types/string.h"

namespace yaramod {

/**
 * Class representing plain strings in the strings section
 * of the YARA rules.
 *
 * For example:
 * @code
 * $hello = "Hello World!"
 * $bye = "Bye World!" wide
 * @endcode
 */
class PlainString : public String
{
public:
	/// @name Constructors
	/// @{
	explicit PlainString(const std::string& text);
	explicit PlainString(std::string&& text);
	~PlainString() = default;
	/// @}

	/// @name String representation
	/// @{
	virtual std::string getText() const override;
	virtual std::string getPureText() const override;
	/// @}

private:
	std::string _text; ///< Text of the plain string
};

}
