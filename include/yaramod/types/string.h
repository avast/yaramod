/**
 * @file src/types/string.h
 * @brief Declaration of class String.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

#include <string>
#include <vector>

#include "yaramod/types/token_stream.h"
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
	explicit String(const std::shared_ptr<TokenStream>& ts, Type type)
		: _tokenStream(ts)
		, _type(type)
		, _mods(Modifiers::None)
	{
		assert(_tokenStream);
	}
	explicit String(const std::shared_ptr<TokenStream>& ts, Type type, const std::string& id)
		: _tokenStream(ts)
		, _type(type)
		, _mods(Modifiers::None)
	{
		assert(_tokenStream);
		_id = _tokenStream->emplace_back(STRING_KEY, id);
		_assign_token = _tokenStream->emplace_back(ASSIGN, "=");
	}
	explicit String(const std::shared_ptr<TokenStream>& ts, Type type, TokenIt id, TokenIt assign_token, uint32_t mods, std::vector<TokenIt> mods_strings)
		: _tokenStream(ts)
		, _type(type)
		, _id(id)
		, _assign_token(assign_token)
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
		if (_id)
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

	const std::shared_ptr<TokenStream>& getTokenStream() const { return _tokenStream; }

	virtual TokenIt getFirstTokenIt() const = 0;
	/// @}

	/// @name Setter methods
	/// @{
	template <typename Str>
	void setIdentifier(Str&& id)
	{
		if (_id)
			_id.value()->setValue(std::forward<Str>(id));
		else
		{
			auto first = getFirstTokenIt();
			_id = _tokenStream->emplace(first, STRING_KEY, std::forward<Str>(id));
			_assign_token = _tokenStream->emplace(first, ASSIGN, "=");
		}
	}

	void setIdentifier(TokenIt id, TokenIt assign_token)
	{
		setIdentifier(id);
		_assign_token = assign_token;
	}

	void setIdentifier(TokenIt id)
	{
		if (!id->isString())
			throw YaramodError("String class identifier type must be string");
		if (_id && _id.value() != id)
			_tokenStream->erase(_id.value());
		_id = id;
	}

	// use only when not care about the order of mods in tokenstream
	void setModifiers(std::uint32_t mods, bool avoidSingleAscii = false)
	{
		if (_mods != mods)
		{
			_mods = mods;

			TokenIt behind_last_erased = _tokenStream->end();

			for (const TokenIt& it : _mods_strings)
				behind_last_erased = _tokenStream->erase(it);

			_mods_strings = std::vector<TokenIt>();
			if (_mods & Modifiers::Ascii)
			{
				if (_mods == Modifiers::Ascii && avoidSingleAscii)
					return;
				else
					_mods_strings.push_back(_tokenStream->emplace(behind_last_erased, MODIFIER, "ascii"));
			}
			if (_mods & Modifiers::Wide)
				_mods_strings.push_back(_tokenStream->emplace(behind_last_erased, MODIFIER, "wide"));
			if (_mods & Modifiers::Nocase)
				_mods_strings.push_back(_tokenStream->emplace(behind_last_erased, MODIFIER, "nocase"));
			if (_mods & Modifiers::Fullword)
				_mods_strings.push_back(_tokenStream->emplace(behind_last_erased, MODIFIER, "fullword"));
			if (_mods & Modifiers::Xor)
				_mods_strings.push_back(_tokenStream->emplace(behind_last_erased, MODIFIER, "xor"));
		}
	}

	void setModifiers(std::uint32_t mods, std::vector<TokenIt>&& mods_strings)
	{
		if (_mods != mods)
		{
			_mods = mods;

			//delete current modifiers
			for (const TokenIt& it : _mods_strings)
				_tokenStream->erase(it);

			_mods_strings = std::move(mods_strings);
		}
	}
	// Adds modifier only when not present. Otherwise false is returned.
	// The mod's token is emplaced at the end of the tokenStream (that is needed if we want to put a comment in between modifiers)
	bool addModifier(String::Modifiers mod)
	{
		if (_mods && mod) //mod already present
			return false;
		else
		{
			_mods += mod;
			TokenIt it;
			if (mod & Modifiers::Ascii)
				it = _tokenStream->emplace_back(MODIFIER, "ascii");
			else if (mod & Modifiers::Wide)
				it = _tokenStream->emplace_back(MODIFIER, "wide");
			else if (mod & Modifiers::Nocase)
				it = _tokenStream->emplace_back(MODIFIER, "nocase");
			else if (mod & Modifiers::Fullword)
				it = _tokenStream->emplace_back(MODIFIER, "fullword");
			else if (mod & Modifiers::Xor)
				it = _tokenStream->emplace_back(MODIFIER, "xor");
			_mods_strings.push_back(it);
			return true;
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
	std::optional<TokenIt> _assign_token; ///< Identifier //string
	std::uint32_t _mods; ///< String modifiers //std::uint32_t
	std::vector<TokenIt> _mods_strings; //This is ambiguous with _mods, but for performance. This class alone is responsible for coherent representation of _mods.
};

}
