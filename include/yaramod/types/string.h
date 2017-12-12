/**
 * @file src/types/string.h
 * @brief Declaration of class String.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

#include <string>

namespace yaramod {

/**
 * Abstract class for representing string in YARA rules.
 * This class is subclassed into @c PlainString, @c HexString
 * and @c Regexp. It can be also subclassed to any further types
 * added in the future.
 */
class String
{
public:
	/// Type of string.
	enum class Type
	{
		Plain,
		Hex,
		Regexp
	};

	/// String modifiers mask. These can be used only for certain string types.
	enum Modifiers : std::uint32_t
	{
		None = 0,
		Ascii = 1,
		Wide = 2,
		Nocase = 4,
		Fullword = 8
	};

	/// @name Constructors
	/// @{
	explicit String(Type type) : _type(type), _id(), _mods(Modifiers::None) {}
	virtual ~String() = default;
	/// @}

	/// @name String representation
	/// @{
	virtual std::string getText() const = 0;
	virtual std::string getPureText() const = 0;
	/// @}

	/// @name Getter methods
	/// @{
	Type getType() const { return _type; }
	const std::string& getIdentifier() const { return _id; }
	std::string getModifiersText() const
	{
		// ASCII modifier is default so just don't write anything if its the only one
		if (_mods == Modifiers::None || _mods == Modifiers::Ascii)
			return std::string();

		std::string text;
		if (_mods & Modifiers::Ascii)
			text += " ascii";

		if (_mods & Modifiers::Wide)
			text += " wide";

		if (_mods & Modifiers::Nocase)
			text += " nocase";

		if (_mods & Modifiers::Fullword)
			text += " fullword";

		return text;
	}
	/// @}

	/// @name Setter methods
	/// @{
	void setIdentifier(std::string&& id) { _id = std::move(id); }
	void setIdentifier(const std::string& id) { _id = id; }
	void setModifiers(std::uint32_t mods) { _mods = mods; }
	/// @}

	/// @name Detection
	/// @{
	bool isPlain() const { return _type == Type::Plain; }
	bool isHex() const { return _type == Type::Hex; }
	bool isRegexp() const { return _type == Type::Regexp; }

	bool isAscii() const { return _mods == Modifiers::None || _mods & Modifiers::Ascii || !(_mods & Modifiers::Wide); }
	bool isWide() const { return _mods & Modifiers::Wide; }
	bool isNocase() const { return _mods & Modifiers::Nocase; }
	bool isFullword() const { return _mods & Modifiers::Fullword; }
	/// @}

protected:
	Type _type; ///< Type of string
	std::string _id; ///< Identifier
	std::uint32_t _mods; ///< String modifiers
};

}
