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
	template <typename KeyT, typename LiteralT>
	explicit Meta(KeyT&& key, LiteralT&& value) : _key(std::forward<KeyT>(key)), _value(std::forward<LiteralT>(value)) {}
	Meta(const Meta& meta) = default;
	Meta(Meta&& meta) = default;
	/// @}

	/// @name Assignment
	/// @{
	Meta& operator=(const Meta&) = default;
	Meta& operator=(Meta&&) = default;
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

	/// @name Setter methods
	/// @{
	void setKey(const std::string& key);
	void setValue(const Literal& value);
	/// @}

private:
	std::string _key; ///< Key
	Literal _value; ///< Value
};

}
