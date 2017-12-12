/**
 * @file src/types/meta.h
 * @brief Declaration of class Meta.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

#include <string>

#include "yaramod/types/literal.h"

namespace yaramod {

/**
 * Class representing meta information
 * in the YARA rules.
 */
class Meta
{
public:
	/// @name Constructors
	/// @{
	explicit Meta(const std::string& key, Literal&& value);
	explicit Meta(std::string&& key, Literal&& value);
	Meta(Meta&& meta) = default;
	Meta(const Meta& meta) = default;
	/// @}

	/// @name String representation
	/// @{
	std::string getText() const;
	/// @}

	/// @name Getter methods
	/// @{
	const std::string& getKey() const;
	const Literal& getValue() const;
	/// @}

private:
	std::string _key; ///< Key
	Literal _value; ///< Value
};

}
