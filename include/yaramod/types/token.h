/**
 * @file src/types/token.h
 * @brief Declaration of class Token.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

#include <list>

#include "yaramod/types/literal.h"
#include "yaramod/types/location.h"
#include "yaramod/yaramod_error.h"

namespace yaramod {

class Token;
using TokenIt = std::list<Token>::iterator;
using TokenConstIt = std::list<Token>::const_iterator;
using TokenItReversed = std::reverse_iterator<TokenIt>;
using TokenConstItReversed = std::reverse_iterator<TokenConstIt>;

/**
 * Represents type of parsed tokens.
 */
enum TokenType
{
	RULE_NAME,
	TAG,
	HEX_ALT, // '|'
	HEX_NIBBLE,
	HEX_WILDCARD,
	HEX_WILDCARD_LOW,
	HEX_WILDCARD_HIGH,
	HEX_JUMP_LEFT_BRACKET, // '['
	HEX_JUMP_RIGHT_BRACKET, // ']'
	HEX_ALT_LEFT_BRACKET, // '('
	HEX_ALT_RIGHT_BRACKET, // ')'
	HEX_JUMP_FIXED,
	HEX_START_BRACKET, // '{'
	HEX_END_BRACKET, // '}'
	NEW_LINE,
	META, // 'meta'
	LQUOTE,
	RQUOTE,
	RULE_END, // '}'
	RULE_BEGIN, // '{'
	RANGE,
	DOT,
	DOUBLE_DOT,
	LT,
	GT,
	LE,
	GE,
	EQ,
	NEQ,
	SHIFT_LEFT,
	SHIFT_RIGHT,
	MINUS,
	PLUS,
	MULTIPLY,
	DIVIDE,
	MODULO,
	BITWISE_XOR,
	BITWISE_AND,
	BITWISE_OR,
	BITWISE_NOT,
	LP,
	RP,
	LCB, // '{'
	RCB, // '}'
	ASSIGN,
	COLON,
	COLON_BEFORE_NEWLINE,
	COMMA,
	PRIVATE,
	GLOBAL,
	NONE,
	RULE,
	STRINGS,
	CONDITION,
	ASCII,
	NOCASE,
	WIDE,
	FULLWORD,
	PRIVATE_STRING_MODIFIER,
	XOR,
	IMPORT_MODULE,
	IMPORT_KEYWORD,
	NOT,
	AND,
	OR,
	ALL,
	ANY,
	OF,
	THEM,
	FOR,
	ENTRYPOINT,
	OP_AT,
	OP_IN,
	FILESIZE,
	CONTAINS,
	MATCHES,
	SLASH,
	STRING_LITERAL,
	INTEGER,
	DOUBLE,
	STRING_ID,
	STRING_ID_BEFORE_NEWLINE,
	STRING_ID_WILDCARD,
	STRING_LENGTH,
	STRING_OFFSET,
	STRING_COUNT,
	ID,
	INTEGER_FUNCTION,
	LSQB, // '['
	RSQB, // ']'
	DASH, // '-'
	REGEXP_OR,
	REGEXP_ITER,
	REGEXP_PITER,
	REGEXP_OPTIONAL,
	REGEXP_START_SLASH,
	REGEXP_END_SLASH,
	REGEXP_CHAR,
	REGEXP_RANGE,
	REGEXP_TEXT,
	REGEXP_CLASS_NEGATIVE,
	REGEXP_MODIFIERS,
	REGEXP_GREEDY,
	UNARY_MINUS,
	META_KEY,
	META_VALUE,
	STRING_KEY,
	VALUE_SYMBOL,
	FUNCTION_SYMBOL,
	ARRAY_SYMBOL,
	DICTIONARY_SYMBOL,
	STRUCTURE_SYMBOL,
	LP_ENUMERATION,
	RP_ENUMERATION,
	LP_WITH_SPACE_AFTER,
	RP_WITH_SPACE_BEFORE,
	LP_WITH_SPACES,
	RP_WITH_SPACES,
	BOOL_TRUE,
	BOOL_FALSE,
	ONELINE_COMMENT,
	COMMENT,
	INCLUDE_DIRECTIVE,
	INCLUDE_PATH,
	FUNCTION_CALL_LP,
	FUNCTION_CALL_RP,
	INVALID,
};

class TokenStream;

/**
 * Class representing tokens that YARA rules consist of. Tokens do not store values and are stored in TokenStream
 */
class Token
{
public:
	Token(TokenType type, const Literal& value)
		: _type(type)
		, _value(std::make_shared<Literal>(value))
		, _location()
		, _wanted_column(0)
	{
	}

	Token(TokenType type, Literal&& value)
		: _type(type)
		, _value(std::make_shared<Literal>(std::move(value)))
		, _location()
		, _wanted_column(0)
	{
	}

	Token(const Token& other) = default;

	Token(Token&& other) = default;

	/// @name String representation
	/// @{
	std::string getText() const { return _value->getText(); }
	std::string getPureText() const { return _value->getPureText(); }
	/// @}

	/// @name Setter methods
	/// @{
	void setValue(const Literal& new_value) { _value = std::make_shared<Literal>(new_value); }

	void setValue(const std::string& value) { _value->setValue(value); }
	void setValue(std::string&& value) { _value->setValue(std::move(value)); }
	void setValue(bool value) { _value->setValue(value); }
	void setValue(int value, const std::optional<std::string>& integral_formated_value = std::nullopt) { _value->setValue(value, integral_formated_value); }
	void setValue(int64_t value, const std::optional<std::string>& integral_formated_value = std::nullopt) { _value->setValue(value, integral_formated_value); }
	void setValue(uint64_t value, const std::optional<std::string>& integral_formated_value = std::nullopt) { _value->setValue(value, integral_formated_value); }
	void setValue(double value, const std::optional<std::string>& integral_formated_value = std::nullopt) { _value->setValue(value, integral_formated_value); }
	void setValue(const std::shared_ptr<Symbol>& value, const std::string& symbol_name) { _value->setValue(value, symbol_name); }
	void setValue(std::shared_ptr<Symbol>&& value, std::string&& symbol_name) { _value->setValue(std::move(value), std::move(symbol_name)); }

	void setType(TokenType type) { _type = type; }
	void setFlag(bool flag) { _flag = flag; }
	void setLocation(const Location& location) { _location = location; }
	void setIndentation(std::size_t wanted_column) { _wanted_column = wanted_column; }
	void markEscaped() { _value->markEscaped(); }
	/// @}

	/// @name Detection methods
	/// @{
	bool isString() const { return _value->is<std::string>(); }
	bool isBool() const { return _value->is<bool>(); }
	bool isInt() const { return _value->is<int>(); }
	bool isInt64() const { return _value->is<int64_t>(); }
	bool isUInt64() const { return _value->is<uint64_t>(); }
	bool isDouble() const { return _value->is<double>(); }
	bool isSymbol() const { return _value->is<std::shared_ptr<Symbol>>(); }

	bool isIntegral() const { return _value->isIntegral(); }

	bool isIncludeToken() const { return _subTokenStream != nullptr; }
	bool isLeftBracket() const
	{
		return _type == TokenType::LP
			|| _type == TokenType::LP_ENUMERATION
			|| _type == TokenType::HEX_JUMP_LEFT_BRACKET
			|| _type == TokenType::REGEXP_START_SLASH
			|| _type == TokenType::HEX_START_BRACKET
			|| _type == TokenType::LP_WITH_SPACE_AFTER
			|| _type == TokenType::LP_WITH_SPACES;
	}

	bool isRightBracket() const
	{
		return _type == TokenType::RP
			|| _type == TokenType::RP_ENUMERATION
			|| _type == TokenType::HEX_JUMP_RIGHT_BRACKET
			|| _type == TokenType::REGEXP_END_SLASH
			|| _type == TokenType::HEX_END_BRACKET
			|| _type == TokenType::RP_WITH_SPACE_BEFORE
			|| _type == TokenType::RP_WITH_SPACES;
	}

	bool isStringModifier() const
	{
		return _type == ASCII
			|| _type == WIDE
			|| _type == FULLWORD
			|| _type == NOCASE
			|| _type == XOR
			|| _type == PRIVATE;
	}
	/// @}

	friend std::ostream& operator<<(std::ostream& os, const Token& token)
	{
		switch(token._type)
		{
			case TokenType::META_VALUE:
			case TokenType::STRING_LITERAL:
			case TokenType::IMPORT_MODULE:
			case TokenType::INCLUDE_PATH:
				return os << token.getText();
			default:
				return os << token.getPureText();
		}
	}

	/// @name Getter methods
	/// @{
	TokenType getType() const { return _type; }
	const Literal& getLiteral() const;
	const std::string& getString() const;
	bool getBool() const;
	int getInt() const;
	int64_t getInt64() const;
	uint64_t getUInt64() const;
	double getDouble() const;
	const std::shared_ptr<Symbol>& getSymbol() const;
	template <typename T>
	const T& getValue() const { return _value->getValue<T>(); }
	bool getFlag() const { return _flag; }
	const Location& getLocation() const { return _location; }
	std::size_t getIndentation() const { return _wanted_column; }
	/// @}

	/// @name Include substream handler methods
	/// @{
	const std::shared_ptr<TokenStream>& getSubTokenStream() const;
	const std::shared_ptr<TokenStream>& initializeSubTokenStream();
	/// @}

private:
	bool _flag = false; // used for '(' to determine it's sector and whether to put newlines
	TokenType _type;
	std::shared_ptr<TokenStream> _subTokenStream = nullptr; // used only for INCLUDE_PATH tokens
	std::shared_ptr<Literal> _value; // pointer to the value owned by the Token
	Location _location; // Location in source input is stored in Tokens for precise error outputs
	std::size_t _wanted_column; // Wanted column where this Literal should be printed. Used for one-line comments.
};

} //namespace yaramod
