#include "yaramod/builder/yara_hex_string_builder.h"

namespace yaramod {

/**
 * Constructor for creating byte without any wildcard.
 *
 * @param byte Byte.
 */
YaraHexStringBuilder::YaraHexStringBuilder()
	: _tokenStream(std::make_shared<TokenStream>())
{
}

/**
 * Constructor for creating byte without any wildcard.
 *
 * @param byte Byte.
 */
YaraHexStringBuilder::YaraHexStringBuilder(std::uint8_t byte)
	: _tokenStream(std::make_shared<TokenStream>())
	, _units()
{
	TokenIt t1 = _tokenStream->emplace_back(TokenType::HEX_NIBBLE, (byte & 0xF0) >> 4);
	TokenIt t2 = _tokenStream->emplace_back(TokenType::HEX_NIBBLE, (byte & 0x0F));
	_units.push_back(std::make_shared<HexStringNibble>(t1));
	_units.push_back(std::make_shared<HexStringNibble>(t2));
}

/**
 * Constructor for creating sequence of bytes without any wildcard.
 *
 * @param bytes Bytes.
 */
YaraHexStringBuilder::YaraHexStringBuilder(const std::vector<std::uint8_t>& bytes)
	: _tokenStream(std::make_shared<TokenStream>())
	, _units()
{
	_units.reserve(2 * bytes.size());
	for (auto byte : bytes)
	{
		TokenIt t1 = _tokenStream->emplace_back(TokenType::HEX_NIBBLE, (byte & 0xF0) >> 4);
		TokenIt t2 = _tokenStream->emplace_back(TokenType::HEX_NIBBLE, (byte & 0x0F));
		_units.push_back(std::make_shared<HexStringNibble>(t1));
		_units.push_back(std::make_shared<HexStringNibble>(t2));
	}
}

/**
 * Constructor for creating custom unit.
 *
 * @param unit Hex string unit.
 */
YaraHexStringBuilder::YaraHexStringBuilder(const std::shared_ptr<HexStringUnit>& unit)
	: _tokenStream(std::make_shared<TokenStream>())
	, _units()
{
	_units.push_back(unit);
}

/**
 * Constructor for creating custom unit.
 *
 * @param unit Hex string unit.
 */
YaraHexStringBuilder::YaraHexStringBuilder(std::shared_ptr<HexStringUnit>&& unit) : _tokenStream(std::make_shared<TokenStream>()), _units()
{
	_units.push_back(std::move(unit));
}

/**
 * Constructor for creating custom units.
 *
 * @param units Hex string units.
 */
YaraHexStringBuilder::YaraHexStringBuilder(const std::vector<std::shared_ptr<HexStringUnit>>& units)
 	: _tokenStream(std::make_shared<TokenStream>())
 	, _units(units)
{
}

/**
 * Constructor for creating custom units.
 *
 * @param units Hex string units.
 */
YaraHexStringBuilder::YaraHexStringBuilder(std::vector<std::shared_ptr<HexStringUnit>>&& units)
	: _tokenStream(std::make_shared<TokenStream>())
	, _units(std::move(units))
{
}

/**
 * Constructor for creating byte without any wildcard.
 *
 * @param byte Byte.
 */
YaraHexStringBuilder::YaraHexStringBuilder(std::shared_ptr<TokenStream>& ts, std::uint8_t byte)
	: _tokenStream(ts)
	, _units()
{
		TokenIt t1 = _tokenStream->emplace_back(TokenType::HEX_NIBBLE, (byte & 0xF0) >> 4);
		TokenIt t2 = _tokenStream->emplace_back(TokenType::HEX_NIBBLE, (byte & 0x0F));
		_units.push_back(std::make_shared<HexStringNibble>(t1));
		_units.push_back(std::make_shared<HexStringNibble>(t2));
}

/**
 * Constructor for creating sequence of bytes without any wildcard.
 *
 * @param bytes Bytes.
 */
YaraHexStringBuilder::YaraHexStringBuilder(std::shared_ptr<TokenStream>& ts, const std::vector<std::uint8_t>& bytes)
	: _tokenStream(ts)
	, _units()
{
	_units.reserve(2 * bytes.size());
	for (auto byte : bytes)
	{
		TokenIt t1 = _tokenStream->emplace_back(TokenType::HEX_NIBBLE, (byte & 0xF0) >> 4);
		TokenIt t2 = _tokenStream->emplace_back(TokenType::HEX_NIBBLE, (byte & 0x0F));
		_units.push_back(std::make_shared<HexStringNibble>(t1));
		_units.push_back(std::make_shared<HexStringNibble>(t2));
	}
}

/**
 * Constructor for creating custom unit.
 *
 * @param unit Hex string unit.
 */
YaraHexStringBuilder::YaraHexStringBuilder(std::shared_ptr<TokenStream>& ts, const std::shared_ptr<HexStringUnit>& unit)
	: _tokenStream(ts)
	, _units()
{
	_units.push_back(unit);
}

/**
 * Constructor for creating custom unit.
 *
 * @param unit Hex string unit.
 */
YaraHexStringBuilder::YaraHexStringBuilder(std::shared_ptr<TokenStream>& ts, std::shared_ptr<HexStringUnit>&& unit)
	: _tokenStream(ts)
	, _units()
{
	_units.push_back(std::move(unit));
}

/**
 * Constructor for creating custom units.
 *
 * @param units Hex string units.
 */
YaraHexStringBuilder::YaraHexStringBuilder(std::shared_ptr<TokenStream>& ts, const std::vector<std::shared_ptr<HexStringUnit>>& units)
	: _tokenStream(ts)
	, _units(units)
{
}

/**
 * Constructor for creating custom units.
 *
 * @param units Hex string units.
 */
YaraHexStringBuilder::YaraHexStringBuilder(std::shared_ptr<TokenStream>& ts, std::vector<std::shared_ptr<HexStringUnit>>&& units)
	: _tokenStream(ts)
	, _units(std::move(units))
{
}

/**
 * Returns the built hex string and resets the builder back to default state.
 *
 * @param acceptor TokenStream to move-append all our tokens
 * @return Built hex string.
 */
std::shared_ptr<HexString> YaraHexStringBuilder::get(std::shared_ptr<TokenStream> acceptor /*= nullptr*/) const
{
	if( acceptor)
	{
		acceptor->move_append(_tokenStream.get());
		std::cout << "TokenStream when YaraHexStringBuilder::get: --with acceptor" << std::endl << *acceptor << std::endl;
		return std::make_shared<HexString>(acceptor, _units);
	}
	else
	{
		std::cout << "TokenStream when YaraHexStringBuilder::get: -- without acceptor" << std::endl << *_tokenStream << std::endl;
		return std::make_shared<HexString>(_tokenStream, _units);
	}
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
	auto ts = std::make_shared<TokenStream>();
	std::vector<std::shared_ptr<HexStringUnit>> units;
	ts->emplace_back(TokenType::HEX_WILDCARD_FULL, Literal( "??" ));
	units.push_back(std::make_shared<HexStringWildcard>());
	units.push_back(std::make_shared<HexStringWildcard>());
	return YaraHexStringBuilder(ts, std::move(units));
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
	auto ts = std::make_shared<TokenStream>();
	std::vector<std::shared_ptr<HexStringUnit>> units;
	auto t = ts->emplace_back(TokenType::HEX_NIBBLE, Literal(high));
	units.push_back(std::make_shared<HexStringNibble>(t));
	ts->emplace_back(TokenType::HEX_WILDCARD_LOW, Literal("?"));
	units.push_back(std::make_shared<HexStringWildcard>());
	return YaraHexStringBuilder(ts, std::move(units));
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
	auto ts = std::make_shared<TokenStream>();
	std::vector<std::shared_ptr<HexStringUnit>> units;
	ts->emplace_back(TokenType::HEX_WILDCARD_HIGH, Literal("?"));
	units.push_back(std::make_shared<HexStringWildcard>());
	auto t = ts->emplace_back(TokenType::HEX_NIBBLE, Literal(low));
	units.push_back(std::make_shared<HexStringNibble>(t));
	return YaraHexStringBuilder(ts, std::move(units));
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
	auto ts = std::make_shared<TokenStream>();
	ts->emplace_back(TokenType::LP, Literal("["));
	ts->emplace_back(TokenType::DASH, Literal("-"));
	ts->emplace_back(TokenType::RP, Literal("]"));
	return YaraHexStringBuilder(ts, std::make_shared<HexStringJump>());
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
	auto ts = std::make_shared<TokenStream>();
	ts->emplace_back(TokenType::LP, Literal("["));
	TokenIt t = ts->emplace_back(TokenType::HEX_NIBBLE, value);
	ts->emplace_back(TokenType::RP, Literal("]"));

	return YaraHexStringBuilder(ts, std::make_shared<HexStringJump>(t, t));
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
	auto ts = std::make_shared<TokenStream>();
	ts->emplace_back(TokenType::LP, Literal("["));
	TokenIt t = ts->emplace_back(TokenType::HEX_NIBBLE, low);
	ts->emplace_back(TokenType::RP, Literal("]"));

	return YaraHexStringBuilder(ts, std::make_shared<HexStringJump>(t));
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
	auto ts = std::make_shared<TokenStream>();
	ts->emplace_back(TokenType::LP, Literal("["));
	TokenIt t1 = ts->emplace_back(TokenType::HEX_NIBBLE, low);
	ts->emplace_back(TokenType::DASH, Literal("-"));
	TokenIt t2 = ts->emplace_back(TokenType::HEX_NIBBLE, high);
	ts->emplace_back(TokenType::RP, Literal("]"));

	return YaraHexStringBuilder(ts, std::make_shared<HexStringJump>(t1, t2));
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

	auto ts = std::make_shared<TokenStream>();
	for( size_t i = 0; i < units.size(); ++i )
	{
		hexStrings.push_back( units[i].get(ts) ); //filling up ts while getting the hexStrings
		if(i + 1 < units.size()) {
			ts->emplace_back( HEX_ALT, "|" ); // add '|' in between the hexStrings
		}
	}
	std::cout << "Made alt from " << units.size() << " units. The TokenStream: " << std::endl << *ts << std::endl;
	return YaraHexStringBuilder( ts, std::make_shared< HexStringOr >(hexStrings) );
}

YaraHexStringBuilder _alt(std::shared_ptr<TokenStream> ts, std::vector<std::shared_ptr<HexString>>& hexStrings, const YaraHexStringBuilder& unit)
{
	hexStrings.push_back(unit.get(ts));
	return YaraHexStringBuilder( ts, std::make_shared< HexStringOr >(hexStrings) );
}

}

