/**
 * @file src/types/literal.h
 * @brief Declaration of class Literal.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

#include <cassert>
#include <iostream>
#include <iterator>
#include <list>
#include <memory>
#include <optional>
#include <string>
#include <sstream>
#include <variant>

namespace yaramod {

/**
 * Represents type of parsed tokens.
 */
enum TokenType
{
   RULE_NAME = 1,
   TAG = 2,
   RULE_END = 3,
   FILE_END = 4,
   HEX_ALT = 6,
   HEX_NORMAL = 7,
   HEX_WILDCARD_FULL = 8,
   HEX_WILDCARD_LOW = 9,
   HEX_WILDCARD_HIGH = 10,
   HEX_JUMP_VARYING = 11,
   HEX_JUMP_VARYING_RANGE = 12,
   HEX_JUMP_RANGE = 13,
   HEX_JUMP_FIXED = 14,
   HEX_LEFT_BRACKET = 15,
   HEX_RIGHT_BRACKET = 16,
   NEW_LINE = 17,
   COMMENT = 18,
   META = 19,       //carries 'meta:'
   META_END = 20,   //only marker which does not carry any value

   END = 258,
   RANGE = 259,
   DOT = 260,
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
   LCB = 280,
   RCB = 281,
   ASSIGN = 282,
   COLON = 283,
   COMMA = 284,
   PRIVATE = 285,
   GLOBAL = 286,
   RULE = 287,
   STRINGS = 289,
   CONDITION = 290,
   ASCII = 291,
   NOCASE = 292,
   WIDE = 293,
   FULLWORD = 294,
   XOR = 295,
   BOOL_TRUE = 296,
   BOOL_FALSE = 297,
   IMPORT_MODULE = 298,
   NOT = 299,
   AND = 300,
   OR = 301,
   ALL = 302,
   ANY = 303,
   OF = 304,
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
   LSQB = 325,
   RSQB = 326,
   DASH = 328,
   REGEXP_OR = 331,
   REGEXP_ITER = 332,
   REGEXP_PITER = 333,
   REGEXP_OPTIONAL = 334,
   REGEXP_START_OF_LINE = 335,
   REGEXP_END_OF_LINE = 336,
   REGEXP_ANY_CHAR = 337,
   REGEXP_WORD_CHAR = 338,
   REGEXP_NON_WORD_CHAR = 339,
   REGEXP_SPACE = 340,
   REGEXP_NON_SPACE = 341,
   REGEXP_DIGIT = 342,
   REGEXP_NON_DIGIT = 343,
   REGEXP_WORD_BOUNDARY = 344,
   REGEXP_NON_WORD_BOUNDARY = 345,
   REGEXP_CHAR = 346,
   REGEXP_RANGE = 347,
   REGEXP_CLASS = 348,
   UNARY_MINUS = 349,
   META_KEY = 288,
   META_VALUE = 289,
   STRING_KEY = 290,
   PLAIN_STRING_VALUE = 291,

   INVALID = 16384
};

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
	Literal() = default;
	explicit Literal(const std::string& value);
	explicit Literal(std::string&& value);
	explicit Literal(bool boolValue);
	explicit Literal(int value, const std::optional<std::string>& integral_formated_value = std::nullopt);
	explicit Literal(int64_t value, const std::optional<std::string>& integral_formated_value = std::nullopt);
	explicit Literal(uint8_t value, const std::optional<std::string>& integral_formated_value = std::nullopt);
	explicit Literal(uint64_t value, const std::optional<std::string>& integral_formated_value = std::nullopt);
	explicit Literal(float value, const std::optional<std::string>& integral_formated_value = std::nullopt);

	Literal(Literal&& literal) = default;
	Literal(const Literal& literal) = default;
	Literal& operator=(Literal&& literal) = default;
	Literal& operator=(const Literal& literal) = default;
	/// @}

	/// @name String representation
	/// @{
	std::string getText( bool pure = false ) const;
	std::string getPureText() const;
	/// @}

   /// @name Setter methods
   /// @{
   void setValue(const std::string& s);
   void setValue(bool b);
   void setValue(int i, const std::optional<std::string>& integral_formated_value = std::nullopt);
   void setValue(int64_t i, const std::optional<std::string>& integral_formated_value = std::nullopt);
   void setValue(uint8_t i, const std::optional<std::string>& integral_formated_value = std::nullopt);
   void setValue(uint64_t i, const std::optional<std::string>& integral_formated_value = std::nullopt);
   void setValue(float f, const std::optional<std::string>& integral_formated_value = std::nullopt);
   /// @}

   /// @name Getter methods
   /// @{
   const std::string& getString() const;
   bool getBool() const;
   int getInt() const;
   int64_t getInt64_t() const;
   uint64_t getUInt8_t() const;
   uint64_t getUInt64_t() const;
   float getFloat() const;
   /// @}

	/// @name Detection methods
	/// @{
	bool isString() const;
	bool isBool() const;
	bool isInt() const;
	bool isInt64_t() const;
	bool isUInt8_t() const;
	bool isUInt64_t() const;
	bool isFloat() const;

	bool isIntegral() const;
	/// @}

	friend std::ostream& operator<<(std::ostream& os, const Literal& literal) {
      if( literal._integral_formated_value.has_value() )
      	os << literal._integral_formated_value.value();
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
	/// i.  x it is unformatted, thus _int_formated_value is empty and _value contains x
	/// ii. x it is formatted,     so _int_formated_value contains x's string representation and _value contains pure x
	std::variant< std::string, bool, int, int64_t, uint8_t, uint64_t, float > _value; ///< Value used for all literals:
	std::optional< std::string > _integral_formated_value; ///< Value used for integral literals with particular formatting
};


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
   void setValue(bool value) { _value->setValue(value); }
   void setValue(int value) { _value->setValue(value); }
   void setValue(int64_t value) { _value->setValue(value); }
   void setValue(uint8_t value) { _value->setValue(value); }
   void setValue(uint64_t value) { _value->setValue(value); }
   void setValue(float value) { _value->setValue(value); }
   /// @}

   /// @name Detection methods
	/// @{
	bool isString() const { return _value->isString(); }
	bool isBool() const { return _value->isBool(); }
	bool isInt() const { return _value->isInt(); }
	bool isFloat() const { return _value->isFloat(); }

	bool isIntegral() const { return _value->isIntegral(); }
	/// @}

   /// @name Getter methods
   /// @{
   TokenType getType() const { return _type; }
	const Literal& getValue() { return *_value; }

   const std::string& getString() const;
   bool getBool() const;
   int getInt() const;
   int64_t getInt64_t() const;
   uint8_t getUInt8_t() const;
   uint64_t getUInt64_t() const;
   float getFloat() const;
   /// @}

private:
   TokenType _type;
   std::shared_ptr< Literal > _value; // pointer to the value owned by the Token
};


using TokenIt = std::list< Token >::iterator;

class TokenStream
{
public:
	TokenStream() = default;
	/// @name Insertion methods
	/// @{
	TokenIt emplace_back( TokenType type, const std::string& value );
	TokenIt emplace_back( TokenType type, bool b );
	TokenIt emplace_back( TokenType type, int i, const std::optional<std::string>& integral_formated_value = std::nullopt );
	TokenIt emplace_back( TokenType type, int64_t i, const std::optional<std::string>& integral_formated_value = std::nullopt );
	TokenIt emplace_back( TokenType type, uint64_t i, const std::optional<std::string>& integral_formated_value = std::nullopt );
	TokenIt emplace_back( TokenType type, float i, const std::optional<std::string>& integral_formated_value = std::nullopt );
	TokenIt emplace_back( TokenType type, const Literal& literal );
	TokenIt emplace_back( TokenType type, Literal&& literal );
	TokenIt push_back( const Token& t );
	TokenIt push_back( Token&& t );
	TokenIt insert( TokenIt before, TokenType type, const Literal& literal);
	TokenIt insert( TokenIt before, TokenType type, Literal&& literal);
	void move_append( TokenStream& donor );
	/// @}

	/// @name Iterators
	/// @{
	TokenIt begin();
	TokenIt end();
	/// @}

	TokenIt find( TokenType type );
	TokenIt find( TokenType type, TokenIt from );
	TokenIt find( TokenType type, TokenIt from, TokenIt to );

	/// @name Reseting methods
	void clear();
	/// @}
private:
	std::list< Token > _tokens;
};


} //namespace yaramod


// /**
//  * Class representing token values that YARA rules consist of. The values are stored in our inner representation, not the tokenstream.
//  */
// class TokenValue// : public TokenValueBase
// {
// public:
//    /// @name Constructors
//    /// @{
//    TokenValue() = default;
//    TokenValue(int value) : value(value) {}
//    TokenValue(uint value) : value(value) {}
//    TokenValue(bool value) : value(value) {}
//    TokenValue(int64_t value) : value(value) {}
//    TokenValue(long unsigned int value) : value(value) {}
//    TokenValue(const std::string& value) : value(value) {}

//    TokenValue(TokenValue&& other) = default;
//    TokenValue(const TokenValue& other) = default;
//    /// @}

//    /// @name Assignment
//    /// @{
//    TokenValue& operator=(TokenValue&& other) = default;
//    TokenValue& operator=(const TokenValue& other) = default;
//    /// @}

//    /// @name Detection methods
//    /// @{
//    bool isBool() const
//    {
//       return std::is_same_v< decltype(value), bool& >;
//    }
//    bool isInt() const
//    {
//       return std::is_same_v< decltype(value), int& >;
//    }
//    bool isUint() const
//    {
//       return std::is_same_v< decltype(value), uint& >;
//    }
//    bool isUint64_t() const
//    {
//       return std::is_same_v< decltype(value), uint64_t& >;
//    }
//    bool isLongUnsignedInt() const
//    {
//       return std::is_same_v< decltype(value), long unsigned int& >;
//    }
//    bool isIntegral() const
//    {
//       return isInt() || isUint() || isUint64_t() || isLongUnsignedInt();
//    }
//    bool isString() const
//    {
//       return std::is_same_v< decltype(value), std::string& >;
//    }

//    friend std::ostream& operator<<(std::ostream& os, const TokenValue& token_value) {
//       std::visit(
//       [&os](auto&& v)
//          {
//             os << v;
//          },
//          token_value.value
//       );
//       return os;
//    }
//    /// @}

//    /// @name String representation
//    /// @{
//    std::string getText() const
//    {
//       std::stringstream ss;
//       if( isString() )
//          ss << "\"" << *this << "\"";
//       else
//          ss << *this;
//       return ss.str();
//    }

//    std::string getPureText() const
//    {
//       std::stringstream ss;
//       ss << *this;
//       return ss.str();
//    }
//    /// @}

//    /// @name Setter methods
//    /// @{
//    void setValue(int i) { value = i; }
//    void setValue(uint i) { value = i; }
//    void setValue(int64_t i) { value = i; }
//    void setValue(float i) { value = i; }
//    void setValue(long unsigned int i) { value = i; }
//    void setValue(bool b) { value = b; }
//    void setValue(const std::string& s) { value = s; }
//    /// @}

//    /// @name Getter methods
//    /// @{
//    int getIntegral() const
//    {
//       if(isInt())
//          return std::get<int>(value);
//       else if(isUint())
//          return std::get<uint>(value);
//       else if(isUint64_t())
//          return std::get<int64_t>(value);
//       else
//       {
//          std::cerr << "Called getIntegral() of a TokenValue which holds " << *this << ". Index = " << value.index() << std::endl;
//          assert(false && "Called getIntegral() of non-integral TokenValue");
//       }
//    }

//    float getFloat() const
//    {
//       try{
//          return std::get<float>(value);
//       }
//       catch (std::bad_variant_access& exp)
//       {
//          std::cerr << "Called getFloat() of a TokenValue which holds " << *this << ". Index = " << value.index() << std::endl << exp.what() << std::endl;
//          assert(false && "Called getFloat() of non-float TokenValue");
//       }
//    }

//    bool getBool() const
//    {
//       try{
//          return std::get<bool>(value);
//       }
//       catch (std::bad_variant_access& exp)
//       {
//          std::cerr << "Called getBool() of a TokenValue which holds " << *this << ". Index = " << value.index() << std::endl << exp.what() << std::endl;
//          assert(false && "Called getBool() of non-bool TokenValue");
//       }
//    }

//    const std::string& getString() const
//    {
//       try{
//          return std::get<std::string>(value);
//       }
//       catch (std::bad_variant_access& exp)
//       {
//          std::cerr << "Called getString() of a TokenValue which holds " << *this << ". Index = " << value.index() << std::endl << exp.what() << std::endl;
//          assert(false && "Called getString() of non-string TokenValue");
//       }
//    }
//    /// @}

// private:
//    std::variant<int, uint, int64_t, long unsigned int, float,  bool, std::string> value;
// };


/**
 * Abstract class representing token values that YARA rules consist of. The values are stored in our inner representation, not the tokenstream.
 */

// class TokenValueBase
// {
// public:
// 	/// This constructor is used for only tokens that we do not want in our inner representation (comments, operator =, etc.)
//    TokenValueBase( TokenStream& token_stream, const std::string& value )
//    	: _value( value )
//    	, _token(  )
//    {

//    }

//    virtual std::string getPureText() const;
//    virtual std::string getText() const;
//    Token* _token;
// };
