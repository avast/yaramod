/**
 * @file src/types/literal.h
 * @brief Declaration of class Literal.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

#include <cassert>
#include <iostream>
#include <iterator>
#include <vector>
#include <list>
#include <memory>
#include <optional>
#include <string>
#include <sstream>
#include <variant>

//#include "yaramod/types/symbol.h"

namespace yaramod {

/**
 * Represents type of parsed tokens.
 */
enum TokenType
{
   RULE_NAME = 1,
   TAG = 2,

   HEX_ALT = 6, // '|'
   HEX_NIBBLE = 7,
   HEX_WILDCARD_LOW = 9,
   HEX_WILDCARD_HIGH = 10,
   HEX_JUMP_VARYING = 11,
   HEX_JUMP_VARYING_RANGE = 12,
   HEX_JUMP_LEFT_BRACKET = 13,
   HEX_JUMP_RIGHT_BRACKET = 14,
   HEX_ALT_LEFT_BRACKET = 15,
   HEX_ALT_RIGHT_BRACKET = 16,
   HEX_JUMP_FIXED = 17,
   HEX_START_BRACKET = 20,
   HEX_END_BRACKET = 21,
   NEW_LINE = 22,
   META = 24,       //carries 'meta:'
   META_END = 25,   //only marker which does not carry any value
   MODULE_NAME = 26,
   MODIFIER = 27,
   LQUOTE = 28,
   RQUOTE = 29,
   RULE_END = 256,
   RULE_BEGIN = 257,

   RANGE = 259,
   DOT = 260,
   DOUBLE_DOT,
   LT = 261,
   GT = 262,
   LE = 263,
   GE = 264,
   EQ = 265,
   NEQ = 266,
   SHIFT_LEFT = 267,
   SHIFT_RIGHT = 268,
   MINUS = 269,
   PLUS = 270,
   MULTIPLY = 271,
   DIVIDE = 272,
   MODULO = 273,
   BITWISE_XOR = 274,
   BITWISE_AND = 275,
   BITWISE_OR = 276,
   BITWISE_NOT = 277,
   LP = 278,
   RP = 279,
   LCB = 280, // '{'
   RCB = 281, // '}'
   ASSIGN = 282,
   COLON = 283,
   COMMA = 284,
   PRIVATE = 285,
   GLOBAL = 286,
   NONE = 287,
   RULE = 288,
   STRINGS = 289,
   CONDITION = 290,
   ASCII = 291,
   NOCASE = 292,
   WIDE = 293,
   FULLWORD = 294,
   XOR = 295,
   IMPORT_MODULE = 296,
   IMPORT_KEYWORD = 297,
   NOT = 299,
   AND = 300,
   OR = 301,
   ALL = 302,
   ANY = 303,
   OF = 304,
   IN = 400,
   THEM = 305,
   FOR = 306,
   ENTRYPOINT = 307,
   OP_AT = 308,
   OP_IN = 309,
   FILESIZE = 310,
   CONTAINS = 311,
   MATCHES = 312,
   SLASH = 313,
   STRING_LITERAL = 314,
   INTEGER = 315,
   DOUBLE = 316,
   STRING_ID = 317,
   STRING_ID_WILDCARD = 318,
   STRING_LENGTH = 319,
   STRING_OFFSET = 320,
   STRING_COUNT = 321,
   ID = 322,
   INTEGER_FUNCTION = 323,
   LSQB = 325, // '['
   RSQB = 326, // ']'
   DASH = 328, // '-'
   REGEXP_OR = 331,
   REGEXP_ITER = 332,
   REGEXP_PITER = 333,
   REGEXP_OPTIONAL = 334,
   REGEXP_START_SLASH = 357,
   REGEXP_END_SLASH = 358,
   REGEXP_CHAR = 346,
   REGEXP_RANGE = 347,
   REGEXP_TEXT = 349,
   REGEXP_CLASS_NEGATIVE = 350,

   REGEXP_MODIFIERS = 351,
   REGEXP_GREEDY = 352,
   UNARY_MINUS = 353,
   META_KEY = 354,
   META_VALUE = 355,
   STRING_KEY = 356,
   VALUE_SYMBOL = 360,
   FUNCTION_SYMBOL = 361,
   ARRAY_SYMBOL = 362,
   DICTIONARY_SYMBOL = 363,
   STRUCTURE_SYMBOL = 364,
   LP_ENUMERATION = 366,
   RP_ENUMERATION = 367,
   LP_WITH_SPACE_AFTER = 370,
   RP_WITH_SPACE_BEFORE = 371,
   LP_WITH_SPACES = 372,
   RP_WITH_SPACES = 373,
   NULLSYMBOL = 374,
   BOOL_TRUE = 375,
   BOOL_FALSE = 376,
   ONELINE_COMMENT = 377,
   COMMENT = 378,

   INCLUDE_DIRECTIVE = 379,
   INCLUDE_PATH = 380,
};

class Symbol;

/**
 * Class representing literal. Literal can be either
 * string, integer or boolean. This class can only bear
 * one literal type at the same time. Behavior is undefined
 * when other type than actual type of the literal is requested.
 *
 * Caution: Integral literals are stored as string to preserve base
 * and all preceding zeroes.
 */
class Literal
{
public:
	/// @name Costructors
	/// @{
	Literal() {assert(isString());};
	explicit Literal(const char* value, const std::optional<std::string>& formated_value = std::nullopt);
   explicit Literal(const std::string& value, const std::optional<std::string>& formated_value = std::nullopt);
   explicit Literal(std::string&& value, const std::optional<std::string>& formated_value = std::nullopt);
	explicit Literal(bool boolValue, const std::optional<std::string>& formated_value = std::nullopt);
	explicit Literal(int value, const std::optional<std::string>& integral_formated_value = std::nullopt);
	explicit Literal(int64_t value, const std::optional<std::string>& integral_formated_value = std::nullopt);
	explicit Literal(uint64_t value, const std::optional<std::string>& integral_formated_value = std::nullopt);
	explicit Literal(double value, const std::optional<std::string>& integral_formated_value = std::nullopt);
	explicit Literal(const std::shared_ptr<Symbol>& value, const std::string& name);
	explicit Literal(std::shared_ptr<Symbol>&& value, const std::string& name);

	Literal(Literal&& literal) = default;
	Literal(const Literal& literal) = default;
	Literal& operator=(Literal&& literal) = default;
	Literal& operator=(const Literal& literal) = default;
	/// @}

   /// @name Setter methods
   /// @{
   void setValue(const std::string& s);
   void setValue(std::string&& s);
   void setValue(bool b);
   void setValue(int i, const std::optional<std::string>& integral_formated_value = std::nullopt);
   void setValue(int64_t i, const std::optional<std::string>& integral_formated_value = std::nullopt);
   void setValue(uint64_t i, const std::optional<std::string>& integral_formated_value = std::nullopt);
   void setValue(double f, const std::optional<std::string>& integral_formated_value = std::nullopt);
   void setValue(const std::shared_ptr<Symbol>& s, const std::string& symbol_name);
   void setValue(std::shared_ptr<Symbol>&& s, std::string&& symbol_name);
   /// @}

   /// @name Getter methods
   /// @{
   const std::string& getString() const;
   bool getBool() const;
   int getInt() const;
   int64_t getInt64_t() const;
   uint64_t getUInt64_t() const;
   double getDouble() const;
   const std::shared_ptr<Symbol>& getSymbol() const;

   template<typename T>
   const T& getValue() const
   {
      try
      {
         return std::get<T>(_value);
      }
      catch (std::bad_variant_access& exp)
      {
         std::cerr << "Called getValue<T>() with incompatible type T. TokenValue which holds " << *this << ". Index = " << _value.index() << std::endl << exp.what() << std::endl;
         assert(false && "Called getValue<T>() with incompatible type T.");
      }
   }
   std::string getFormattedValue() const;
   /// @}

   /// @name String representation
   /// @{
   std::string getText( bool pure = false ) const;
   std::string getPureText() const;
   /// @}

	/// @name Detection methods
	/// @{
	bool isString() const;
	bool isBool() const;
	bool isInt() const;
	bool isInt64_t() const;
	bool isUInt64_t() const;
	bool isDouble() const;
	bool isSymbol() const;

	bool isIntegral() const;
	/// @}

	friend std::ostream& operator<<(std::ostream& os, const Literal& literal) {
      if( literal._formated_value.has_value() )
      	os << literal._formated_value.value();
      else if(literal.isBool()){
      	os << (literal.getBool() ? "true" : "false");
      }
      else
	      std::visit(
	      [&os](auto&& v)
	         {
	            os << v;
	         },
	         literal._value
	      );
      return os;
   }

private:
	/// For an integral literal x there are two options:
	/// i.  x it is unformatted:   _formated_value is empty  AND  _value contains x
	/// ii. x it is formatted:     _formated_value contains x's string representation  AND  _value contains pure x
	std::variant< std::string, bool, int, int64_t, uint64_t, double, std::shared_ptr<Symbol> > _value; ///< Value used for all literals:
	std::optional< std::string > _formated_value; ///< Value used for integral literals with particular formatting
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
      , _value(std::make_shared < Literal >(value))
   {
   }

   Token(TokenType type, Literal&& value)
      : _type(type)
      , _value(std::make_shared < Literal >(std::move(value)))
   {
   }

   Token(const Token& other) = default;

   Token(Token&& other) = default;

	/// @name String representation
	/// @{
   std::string getText() const {	return _value->getText(); }
   std::string getPureText() const { return _value->getPureText(); }
   /// @}

   /// @name Setter methods
   /// @{
   void setValue(const Literal& new_value) { _value = std::make_shared< Literal >(new_value); }

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
   /// @}

   /// @name Detection methods
	/// @{
	bool isString() const { return _value->isString(); }
	bool isBool() const { return _value->isBool(); }
	bool isInt() const { return _value->isInt64_t(); }
	bool isInt64_t() const { return _value->isInt64_t(); }
	bool isUInt64_t() const { return _value->isUInt64_t(); }
	bool isDouble() const { return _value->isDouble(); }
	bool isSymbol() const { return _value->isSymbol(); }

	bool isIntegral() const { return _value->isIntegral(); }

   bool isIncludeToken() const { return _includeSubstream != nullptr; }
   bool isLeftBracket() const
   {
      return _type == LP ||
             _type == LP_ENUMERATION ||
             _type == HEX_JUMP_LEFT_BRACKET ||
             _type == REGEXP_START_SLASH ||
             _type == HEX_START_BRACKET ||
             _type == LP_WITH_SPACE_AFTER ||
             _type == LP_WITH_SPACES;
   }
   bool isRightBracket() const
   {
      return _type == RP ||
             _type == RP_ENUMERATION ||
             _type == HEX_JUMP_RIGHT_BRACKET ||
             _type == REGEXP_END_SLASH ||
             _type == HEX_END_BRACKET ||
             _type == RP_WITH_SPACE_BEFORE ||
             _type == RP_WITH_SPACES;
   }
	/// @}

	friend std::ostream& operator<<(std::ostream& os, const Token& token) {
      switch(token._type)
      {
      	case META_VALUE:
      	case STRING_LITERAL:
      	case IMPORT_MODULE:
         case INCLUDE_PATH:
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
   int64_t getInt64_t() const;
   uint64_t getUInt64_t() const;
   double getDouble() const;
   const std::shared_ptr<Symbol>& getSymbol() const;
   template<typename T>
   const T& getValue() const { return _value->getValue<T>(); }
   bool getFlag() const { return _flag; }
   /// @}

   /// @name Include substream handler methods
   /// @{
   std::shared_ptr<TokenStream> getIncludeSubstream() const { return _includeSubstream; }
   void initializeSubstream()
   {
      assert(_includeSubstream == nullptr);
      _includeSubstream = std::make_shared<TokenStream>();
   }
   /// @}

private:
   bool _flag = false; // used for '(' to determine it's sector and whether to put newlines
   TokenType _type;
   std::shared_ptr< TokenStream > _includeSubstream = nullptr; // used only for INCLUDE_PATH tokens
   std::shared_ptr< Literal > _value; // pointer to the value owned by the Token
};

using TokenIt = std::list< Token >::iterator;
using TokenConstIt = std::list< Token >::const_iterator;
using TokenItReversed = std::reverse_iterator<TokenIt>;
using TokenConstItReversed = std::reverse_iterator<TokenConstIt>;

class TokenStream
{
public:
	TokenStream() = default;
	/// @name Insertion methods
	/// @{
	TokenIt emplace_back( TokenType type, char value );
	TokenIt emplace_back( TokenType type, const char* value, const std::optional<std::string>& formatted_value = std::nullopt );
	TokenIt emplace_back( TokenType type, const std::string& value, const std::optional<std::string>& formatted_value = std::nullopt );
	TokenIt emplace_back( TokenType type, std::string&& value, const std::optional<std::string>& formatted_value = std::nullopt );
	TokenIt emplace_back( TokenType type, bool b, const std::optional<std::string>& integral_formated_value = std::nullopt );
	TokenIt emplace_back( TokenType type, int i, const std::optional<std::string>& integral_formated_value = std::nullopt );
	TokenIt emplace_back( TokenType type, int64_t i, const std::optional<std::string>& integral_formated_value = std::nullopt );
	TokenIt emplace_back( TokenType type, uint64_t i, const std::optional<std::string>& integral_formated_value = std::nullopt );
	TokenIt emplace_back( TokenType type, double i, const std::optional<std::string>& integral_formated_value = std::nullopt );
	TokenIt emplace_back( TokenType type, const std::shared_ptr<Symbol>& s, const std::string& symbol_name );
	TokenIt emplace_back( TokenType type, std::shared_ptr<Symbol>&& s, const std::string& symbol_name );
	TokenIt emplace_back( TokenType type, const Literal& literal );
	TokenIt emplace_back( TokenType type, Literal&& literal );
	TokenIt emplace( const TokenIt& before, TokenType type, char value );
	TokenIt emplace( const TokenIt& before, TokenType type, const char* value );
	TokenIt emplace( const TokenIt& before, TokenType type, const std::string& value );
	TokenIt emplace( const TokenIt& before, TokenType type, std::string&& value );
	TokenIt emplace( const TokenIt& before, TokenType type, bool b );
	TokenIt emplace( const TokenIt& before, TokenType type, int i, const std::optional<std::string>& integral_formated_value = std::nullopt );
	TokenIt emplace( const TokenIt& before, TokenType type, int64_t i, const std::optional<std::string>& integral_formated_value = std::nullopt );
	TokenIt emplace( const TokenIt& before, TokenType type, uint64_t i, const std::optional<std::string>& integral_formated_value = std::nullopt );
	TokenIt emplace( const TokenIt& before, TokenType type, const std::shared_ptr<Symbol>& s, const std::string& symbol_name );
	TokenIt emplace( const TokenIt& before, TokenType type, std::shared_ptr<Symbol>&& s, const std::string& symbol_name );
	TokenIt emplace( const TokenIt& before, TokenType type, double i, const std::optional<std::string>& integral_formated_value = std::nullopt );
	TokenIt emplace( const TokenIt& before, TokenType type, const Literal& literal );
	TokenIt emplace( const TokenIt& before, TokenType type, Literal&& literal );
	TokenIt push_back( const Token& t );
	TokenIt push_back( Token&& t );
	TokenIt insert( TokenIt before, TokenType type, const Literal& literal);
	TokenIt insert( TokenIt before, TokenType type, Literal&& literal);
	TokenIt erase( TokenIt element );
	TokenIt erase( TokenIt first, TokenIt last );
	void move_append( TokenStream* donor );
	/// @}

	/// @name Iterators
	/// @{
	TokenIt begin();
	TokenIt end();
	TokenConstIt begin() const;
	TokenConstIt end() const;
	TokenItReversed rbegin();
	TokenItReversed rend();
	TokenConstItReversed rbegin() const;
	TokenConstItReversed rend() const;

	/// @}

	/// @name Capacity
	/// @{
	size_t size() const;
	bool empty() const;
	/// @}

	TokenIt find( TokenType type );
	TokenIt find( TokenType type, TokenIt from );
	TokenIt find( TokenType type, TokenIt from, TokenIt to );
	TokenIt findBackwards(TokenType type);
	TokenIt findBackwards(TokenType type, TokenIt to);
	TokenIt findBackwards(TokenType type, TokenIt from, TokenIt to);

	friend std::ostream& operator<<(std::ostream& os, TokenStream& ts) { return os << ts.getText(false); }

   std::string getText(bool withIncludes = false);

	std::vector<std::string> getTokensAsText() const;


	/// @name Reseting methods
	void clear();
	/// @}
private:
   void autoformat();
   void determineNewlineSectors();
   void addMissingNewLines();
   // int minimalNumberOfTabs(TokenIt from);
	std::list< Token > _tokens; ///< All tokens off the rule
   bool formatted = false; ///< The flag is set once autoformat has been called
};


} //namespace yaramod
