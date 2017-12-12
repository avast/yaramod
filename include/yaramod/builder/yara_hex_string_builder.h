/**
 * @file src/builder/yara_hex_string_builder.h
 * @brief Declaration of class YaraHexStringBuilder.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

#include <iterator>
#include <memory>
#include <vector>

#include "yaramod/types/hex_string.h"

namespace yaramod {

/**
 * Class representing builder of hex strings. You use this builder
 * to specify what you want in your hex string and then you can obtain
 * your hex string by calling method @c get. As soon as @c get is called,
 * builder resets to default state and does not contain any data from
 * the previous build process.
 */
class YaraHexStringBuilder
{
public:
	/// @name Constructors
	/// @{
	YaraHexStringBuilder() = default;
	YaraHexStringBuilder(std::uint8_t byte);
	YaraHexStringBuilder(const std::vector<std::uint8_t>& bytes);
	YaraHexStringBuilder(const std::shared_ptr<HexStringUnit>& unit);
	YaraHexStringBuilder(std::shared_ptr<HexStringUnit>&& unit);
	YaraHexStringBuilder(const std::vector<std::shared_ptr<HexStringUnit>>& units);
	YaraHexStringBuilder(std::vector<std::shared_ptr<HexStringUnit>>&& units);
	YaraHexStringBuilder(const YaraHexStringBuilder&) = default;
	YaraHexStringBuilder(YaraHexStringBuilder&&) = default;
	/// @}

	/// @name Build method
	/// @{
	std::shared_ptr<HexString> get() const;
	/// @}

	/// @name Building methods
	/// @{
	/**
	 * Adds hex strings unit into hex string.
	 *
	 * @param unit Unit to add.
	 *
	 * @return Builder.
	 */
	YaraHexStringBuilder& add(const YaraHexStringBuilder& unit)
	{
		std::copy(unit.getUnits().begin(), unit.getUnits().end(), std::back_inserter(_units));
		return *this;
	}

	/**
	 * Adds hex strings unit into hex string.
	 *
	 * @param unit Unit to add.
	 * @param args Variadic arguments.
	 *
	 * @return Builder.
	 */
	template <typename... Args>
	YaraHexStringBuilder& add(const YaraHexStringBuilder& unit, const Args&... args)
	{
		std::copy(unit.getUnits().begin(), unit.getUnits().end(), std::back_inserter(_units));
		return add(args...);
	}
	/// @}

	/// @name Getter methods
	/// @{
	const std::vector<std::shared_ptr<HexStringUnit>>& getUnits() const;
	/// @}

private:
	std::vector<std::shared_ptr<HexStringUnit>> _units;
};

/// @name Helper functions
/// These functions serve for readable and easy way to construct
/// hex strings using @c YaraHexStringBuilder.
/// @{
YaraHexStringBuilder wildcard();
YaraHexStringBuilder wildcardLow(std::uint8_t high);
YaraHexStringBuilder wildcardHigh(std::uint8_t low);

YaraHexStringBuilder jumpVarying();
YaraHexStringBuilder jumpFixed(std::uint64_t value);
YaraHexStringBuilder jumpVaryingRange(std::uint64_t low);
YaraHexStringBuilder jumpRange(std::uint64_t low, std::uint64_t high);

/**
 * Creates the alternative between multiple hex string units.
 *
 * For example:
 * @code
 * ( 11 | 22 | 33 )
 * @endcode
 *
 * @param args Units.
 *
 * @return Builder.
 */
template <typename... Args>
YaraHexStringBuilder alt(const Args&... args)
{
	std::vector<std::shared_ptr<HexString>> hexStrings;
	return _alt(hexStrings, args...);
}

template <>
YaraHexStringBuilder alt(const std::vector<YaraHexStringBuilder>& units);

YaraHexStringBuilder _alt(std::vector<std::shared_ptr<HexString>>& hexStrings, const YaraHexStringBuilder& unit);

template <typename... Args>
YaraHexStringBuilder _alt(std::vector<std::shared_ptr<HexString>>& hexStrings, const YaraHexStringBuilder& unit, const Args&... args)
{
	hexStrings.push_back(unit.get());
	return _alt(hexStrings, args...);
}
/// @}

}
