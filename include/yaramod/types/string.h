/**
 * @file src/types/string.h
 * @brief Declaration of class String.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

#include <string>
#include <vector>
#include "yaramod/types/literal.h"
#include "yaramod/yaramod_error.h"

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
		Fullword = 8,
		Xor = 16
	};

	/// @name Constructors
	/// @{
	explicit String(Type type)
		: String(std::make_shared<TokenStream>(), type)
	{
	}
	explicit String(std::shared_ptr<TokenStream> ts, Type type)
		: _tokenStream(ts)
		, _type(type)
	{
		assert(_tokenStream);
	}
	explicit String(std::shared_ptr<TokenStream> ts, Type type, const std::string& id)
		: _tokenStream(ts)
		, _type(type)
		, _mods(Modifiers::None)
	{
		// std::cout << "String Constructor" << std::endl;
		assert(_tokenStream);
		_id = _tokenStream->emplace_back(TokenType::STRING_KEY, id);
		// std::cout << "String Constructor" << std::endl;
		_equal_sign = _tokenStream->emplace_back(TokenType::EQ, "=");
		// std::cout << "String Constructor" << std::endl;
	}
	explicit String(std::shared_ptr<TokenStream> ts, Type type, TokenIt id, TokenIt equal_sign, uint32_t mods, std::vector<TokenIt> mods_strings)
		: _tokenStream(ts)
		, _type(type)
		, _id(id)
		, _equal_sign(equal_sign)
		, _mods(mods)
		, _mods_strings(mods_strings)
	{
		assert(_tokenStream);
	}

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
	std::string getIdentifier() const
	{
		if(_id)
			return _id.value()->getPureText();
		else
			return std::string();
	}
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

		if (_mods & Modifiers::Xor)
			text += " xor";

		return text;
	}
	/// @}

	/// @name Setter methods
	/// @{
	void setIdentifier(std::string&& id)
	{
		if(_id)
			_id.value()->setValue(id);
		else
			_id = _tokenStream->emplace_back(TokenType::STRING_KEY, std::move(id));
	}

	void setIdentifier(TokenIt id, TokenIt equal_sign)
	{
		setIdentifier(id);
		_equal_sign = equal_sign;
	}

	void setIdentifier(const std::string& id)
	{
		std::string forward = id;
		setIdentifier(std::move(forward));
	}

	void setIdentifier(TokenIt id)
	{
		if(!id->isString())
			throw YaramodError("String class identifier type must be string");
		if(_id && _id.value() != id)
		{
			_tokenStream->erase(_id.value());
			_tokenStream->erase(_equal_sign.value());
		}
		_id = id;
	}

	// use only when not care about the order of mods in tokenstream
	void setModifiers(std::uint32_t mods)
	{
		if(_mods != mods)
		{
			_mods = mods;

			TokenIt behind_last_erased = _tokenStream->end();

			for(const TokenIt& it : _mods_strings)
				behind_last_erased = _tokenStream->erase(it);

			_mods_strings = std::vector<TokenIt>();
			if (_mods & Modifiers::Ascii)
			{
				auto it = _tokenStream->emplace( behind_last_erased, TokenType::MODIFIER, "ascii" );
				_mods_strings.push_back(it);
			}
			if (_mods & Modifiers::Wide)
			{
				auto it = _tokenStream->emplace( behind_last_erased, TokenType::MODIFIER, "wide" );
				_mods_strings.push_back(it);
			}
			if (_mods & Modifiers::Nocase)
			{
				auto it = _tokenStream->emplace( behind_last_erased, TokenType::MODIFIER, "nocase" );
				_mods_strings.push_back(it);
			}
			if (_mods & Modifiers::Fullword)
			{
				auto it = _tokenStream->emplace( behind_last_erased, TokenType::MODIFIER, "fullword" );
				_mods_strings.push_back(it);
			}
			if (_mods & Modifiers::Xor)
			{
				auto it = _tokenStream->emplace( behind_last_erased, TokenType::MODIFIER, "xor" );
				_mods_strings.push_back(it);
			}
		}
	}

	void setModifiers(std::uint32_t mods, std::vector<TokenIt>&& mods_strings)
	{
		if(_mods != mods)
		{
			_mods = mods;

			for(const TokenIt& it : _mods_strings)
				_tokenStream->erase(it);

			_mods_strings = std::move(mods_strings);
		}
	}
	// Adds modifier only when not present. Otherwise false is returned.
	// !!! The mod's token is emplaced at the end of the tokenStream (that is needed if we want to put a comment in between modifiers)
	bool addModifier(String::Modifiers mod)
	{
		if(_mods && mod) //mod already present
			return false;
		else
		{
			_mods += mod;
			TokenIt it;
			if( mod & Modifiers::Ascii )
				it = _tokenStream->emplace_back(TokenType::MODIFIER, "ascii");
			else if( mod & Modifiers::Wide )
				it = _tokenStream->emplace_back(TokenType::MODIFIER, "wide");
			else if( mod & Modifiers::Nocase )
				it = _tokenStream->emplace_back(TokenType::MODIFIER, "nocase");
			else if( mod & Modifiers::Fullword )
				it = _tokenStream->emplace_back(TokenType::MODIFIER, "fullword");
			else if( mod & Modifiers::Xor )
				it = _tokenStream->emplace_back(TokenType::MODIFIER, "xor");
			_mods_strings.push_back(it);
		}
	}
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
	bool isXor() const { return _mods & Modifiers::Xor; }
	/// @}

protected:
	std::shared_ptr<TokenStream> _tokenStream; ///< shared_pointer to the TokenStream in which the data is stored
	Type _type; ///< Type of string //no need to store type of string in tokenstream - we just store the '"' or '/' characters
	std::optional<TokenIt> _id; ///< Identifier //string
	std::optional<TokenIt> _equal_sign;
	std::uint32_t _mods; ///< String modifiers //std::uint32_t
	std::vector<TokenIt> _mods_strings; //This is ambiguous with _mods, but for performance. This class alone is responsible for coherent representation of _mods.
};

}
