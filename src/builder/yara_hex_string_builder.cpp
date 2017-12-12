#include "yaramod/builder/yara_hex_string_builder.h"

namespace yaramod {

/**
 * Constructor for creating byte without any wildcard.
 *
 * @param byte Byte.
 */
YaraHexStringBuilder::YaraHexStringBuilder(std::uint8_t byte) : _units()
{
	_units.push_back(std::make_shared<HexStringNibble>((byte & 0xF0) >> 4));
	_units.push_back(std::make_shared<HexStringNibble>(byte & 0x0F));
}

/**
 * Constructor for creating sequence of bytes without any wildcard.
 *
 * @param bytes Bytes.
 */
YaraHexStringBuilder::YaraHexStringBuilder(const std::vector<std::uint8_t>& bytes) : _units()
{
	_units.reserve(2 * bytes.size());
	for (auto byte : bytes)
	{
		_units.push_back(std::make_shared<HexStringNibble>((byte & 0xF0) >> 4));
		_units.push_back(std::make_shared<HexStringNibble>(byte & 0x0F));
	}
}

/**
 * Constructor for creating custom unit.
 *
 * @param unit Hex string unit.
 */
YaraHexStringBuilder::YaraHexStringBuilder(const std::shared_ptr<HexStringUnit>& unit) : _units()
{
	_units.push_back(unit);
}

/**
 * Constructor for creating custom unit.
 *
 * @param unit Hex string unit.
 */
YaraHexStringBuilder::YaraHexStringBuilder(std::shared_ptr<HexStringUnit>&& unit) : _units()
{
	_units.push_back(std::move(unit));
}

/**
 * Constructor for creating custom units.
 *
 * @param units Hex string units.
 */
YaraHexStringBuilder::YaraHexStringBuilder(const std::vector<std::shared_ptr<HexStringUnit>>& units) : _units(units)
{
}

/**
 * Constructor for creating custom units.
 *
 * @param units Hex string units.
 */
YaraHexStringBuilder::YaraHexStringBuilder(std::vector<std::shared_ptr<HexStringUnit>>&& units) : _units(std::move(units))
{
}

/**
 * Returns the built hex string and resets the builder back to default state.
 *
 * @return Built hex string.
 */
std::shared_ptr<HexString> YaraHexStringBuilder::get() const
{
	return std::make_shared<HexString>(_units);
}

/**
 * Returns the units already present in the hex string.
 *
 * @return Hex string units.
 */
const std::vector<std::shared_ptr<HexStringUnit>>& YaraHexStringBuilder::getUnits() const
{
	return _units;
}

/**
 * Creates the full wildcard unit.
 *
 * For example:
 * @code
 * ??
 * @endcode
 *
 * @return Builder.
 */
YaraHexStringBuilder wildcard()
{
	std::vector<std::shared_ptr<HexStringUnit>> units;
	units.push_back(std::make_shared<HexStringWildcard>());
	units.push_back(std::make_shared<HexStringWildcard>());
	return YaraHexStringBuilder(std::move(units));
}

/**
 * Creates the wildcard unit with wildcard on low nibble.
 *
 * For example:
 * @code
 * 9?
 * @endcode
 *
 * @param high High nibble.
 *
 * @return Builder.
 */
YaraHexStringBuilder wildcardLow(std::uint8_t high)
{
	std::vector<std::shared_ptr<HexStringUnit>> units;
	units.push_back(std::make_shared<HexStringNibble>(high));
	units.push_back(std::make_shared<HexStringWildcard>());
	return YaraHexStringBuilder(std::move(units));
}

/**
 * Creates the wildcard unit with wildcard on high nibble.
 *
 * For example:
 * @code
 * ?9
 * @endcode
 *
 * @param low Low nibble.
 *
 * @return Builder.
 */
YaraHexStringBuilder wildcardHigh(std::uint8_t low)
{
	std::vector<std::shared_ptr<HexStringUnit>> units;
	units.push_back(std::make_shared<HexStringWildcard>());
	units.push_back(std::make_shared<HexStringNibble>(low));
	return YaraHexStringBuilder(std::move(units));
}

/**
 * Creates the jump unit with no low or high bound.
 *
 * For example:
 * @code
 * [-]
 * @endcode
 *
 * @return Builder.
 */
YaraHexStringBuilder jumpVarying()
{
	return YaraHexStringBuilder(std::make_shared<HexStringJump>());
}

/**
 * Creates the fixed jump unit.
 *
 * For example:
 * @code
 * [5]
 * @endcode
 *
 * @return Builder.
 */
YaraHexStringBuilder jumpFixed(std::uint64_t value)
{
	return YaraHexStringBuilder(std::make_shared<HexStringJump>(value, value));
}

/**
 * Creates the jump unit with just low bound set.
 *
 * For example:
 * @code
 * [5-]
 * @endcode
 *
 * @return Builder.
 */
YaraHexStringBuilder jumpVaryingRange(std::uint64_t low)
{
	return YaraHexStringBuilder(std::make_shared<HexStringJump>(low));
}

/**
 * Creates the jump unit with low and high bound set.
 *
 * For example:
 * @code
 * [5-7]
 * @endcode
 *
 * @return Builder.
 */
YaraHexStringBuilder jumpRange(std::uint64_t low, std::uint64_t high)
{
	return YaraHexStringBuilder(std::make_shared<HexStringJump>(low, high));
}

/**
 * Creates the alternative between multiple hex string units.
 *
 * For example:
 * @code
 * ( 11 | 22 | 33 )
 * @endcode
 *
 * @param units Units.
 *
 * @return Builder.
 */
template <>
YaraHexStringBuilder alt(const std::vector<YaraHexStringBuilder>& units)
{
	std::vector<std::shared_ptr<HexString>> hexStrings;
	hexStrings.reserve(units.size());

	for (const auto& unit : units)
		hexStrings.push_back(unit.get());

	return YaraHexStringBuilder(std::make_shared<HexStringOr>(hexStrings));
}

YaraHexStringBuilder _alt(std::vector<std::shared_ptr<HexString>>& hexStrings, const YaraHexStringBuilder& unit)
{
	hexStrings.push_back(unit.get());
	return YaraHexStringBuilder(std::make_shared<HexStringOr>(hexStrings));
}

}
