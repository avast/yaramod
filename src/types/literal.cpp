/**
 * @file src/types/literal.cpp
 * @brief Implementation of class Literal.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <cassert>
#include <sstream>
#include <algorithm>

#include "yaramod/types/literal.h"
#include "yaramod/utils/utils.h"

namespace yaramod {

/**
 * Returns the string representation of the TokenValueBase.
 *
 * @return String representation.
 */
// std::string TokenValueBase::getText() const
// {
//    std::stringstream ss;
//    ss << token->type;
//    return ss.str();
// }
// std::string TokenValueBase::getPureText() const
// {
//    std::stringstream ss;
//    ss << token->type;
//    return ss.str();
// }


/**
 * Constructor.
 *
 * @param value String value of the literal.
 * @param type Type of the literal.
 */
Literal::Literal(const std::string& value)
	: _value(value)
{
}

/**
 * Constructor.
 *
 * @param value String value of the literal.
 */
Literal::Literal(std::string&& value)
   : _value(std::move(value))
{
}

/**
 * Constructor.
 *
 * @param value Bool value of the literal.
 */
Literal::Literal( bool value )
	: _value( value )
{
}

/**
 * Constructor.
 *
 * @param value integral value of the literal.
 * @param integral_formated_value formatted value of the integral literal.
 */
Literal::Literal( int value, const std::optional<std::string>& integral_formated_value/* = std::nullopt*/ )
   : _value( value )
   , _integral_formated_value( integral_formated_value )
{
}

/**
 * Constructor.
 *
 * @param value integral value of the literal.
 * @param integral_formated_value formatted value of the integral literal.
 */
Literal::Literal( int64_t value, const std::optional<std::string>& integral_formated_value/* = std::nullopt*/ )
   : _value( value )
   , _integral_formated_value( integral_formated_value )
{
}

/**
 * Constructor.
 *
 * @param value integral value of the literal.
 * @param integral_formated_value formatted value of the integral literal.
 */
Literal::Literal( uint64_t value, const std::optional<std::string>& integral_formated_value/* = std::nullopt*/ )
   : _value( value )
   , _integral_formated_value( integral_formated_value )
{
}

/**
 * Constructor.
 *
 * @param value integral value of the literal.
 * @param integral_formated_value formatted value of the integral literal.
 */
Literal::Literal( float value, const std::optional< std::string >& integral_formated_value /*= std::nullopt*/ )
   : _value( value )
   , _integral_formated_value( integral_formated_value )
{
}

void Literal::setValue( const std::string& s )
{
	_value = s;
}

void Literal::setValue( bool b )
{
	_value = b;
}

void Literal::setValue( int i, const std::optional<std::string>& integral_formated_value /*= std::nullopt*/ )
{
	_value = i;
	_integral_formated_value = integral_formated_value;
}

void Literal::setValue( int64_t i, const std::optional<std::string>& integral_formated_value /*= std::nullopt*/ )
{
	_value = i;
	_integral_formated_value = integral_formated_value;
}

void Literal::setValue( uint64_t i, const std::optional<std::string>& integral_formated_value /*= std::nullopt*/ )
{
	_value = i;
	_integral_formated_value = integral_formated_value;
}

void Literal::setValue( float f, const std::optional<std::string>& integral_formated_value /*= std::nullopt*/ )
{
	_value = f;
	_integral_formated_value = integral_formated_value;
}

/**
 * Returns the string representation of the literal.
 *
 * @return String representation.
 */


/*
	bool isString() const;
	bool isBool() const;
	bool isInt() const;
	bool isInt64_t() const;
	bool isUInt64_t() const;
	bool isFloat() const;*/
std::string Literal::getText( bool pure /*= false*/ ) const
{
	if (isString())
	{
		if(pure)
			return std::get<std::string>(_value);
		else if(std::get<std::string>(_value) == "")
			return std::string();
		else
			return '"' + escapeString( std::get<std::string>(_value) ) + '"';
	}
	else if (isBool())
	{
		std::ostringstream ss;
		ss << std::boolalpha << std::get<bool>(_value);
		return ss.str();
	}
	else if (isInt())
	{
		if(_integral_formated_value.has_value())
			return _integral_formated_value.value();
		else
			return numToStr<int>( std::get<int>(_value) );
	}
	else if (isInt64_t())
	{
		if(_integral_formated_value.has_value())
			return _integral_formated_value.value();
		else
			return numToStr<int64_t>( std::get<int64_t>(_value) );
	}
	else if (isUInt64_t())
	{
		if(_integral_formated_value.has_value())
			return _integral_formated_value.value();
		else
			return numToStr<uint64_t>( std::get<uint64_t>(_value) );
	}
	else if (isFloat())
	{
		if(_integral_formated_value.has_value())
			return _integral_formated_value.value();
		else
			return numToStr<float>( std::get<float>(_value) );
	}
	std::cerr << "Unexpected value '" << *this << "'" << std::endl;
	assert(false);
}

/**
 * Returns the string representation but string literals are not enclosed in double quotes.
 *
 * @return String representation.
 */
std::string Literal::getPureText() const
{
	return getText(true);
}

bool Literal::isString() const
{
	// std::cout << *this << " is string? " << std::is_same_v< decltype(_value), const std::string& > << std::endl;
	// std::cout << *this << " is string? " << std::is_same_v< decltype(_value), std::string& > << std::endl;
	// std::cout << *this << " is string? " << std::is_same_v< decltype(_value), std::string > << std::endl;
	// std::cout << *this << " is string? " << std::is_same_v< decltype(_value), const char* > << std::endl;
	std::cout << "isString(" << *this << ")? index: " << _value.index() << std::endl;
	// return std::is_same_v< decltype(_value), std::string& >;
	return _value.index() == 0;
}

bool Literal::isBool() const
{
	std::cout << "isBool(" << *this << ")? index: " << _value.index() << std::endl;
	return _value.index() == 1;
}

bool Literal::isInt() const
{
	std::cout << "isInt(" << *this << ")? index: " << _value.index() << std::endl;
	return _value.index() == 2;
}

bool Literal::isInt64_t() const
{
	std::cout << "isInt64_t(" << *this << ")? index: " << _value.index() << std::endl;
	return _value.index() == 3;
}

bool Literal::isUInt64_t() const
{
	std::cout << "isUInt64_t(" << *this << ")? index: " << _value.index() << std::endl;
	return _value.index() == 4;
}

bool Literal::isFloat() const
{
	std::cout << "isFloat(" << *this << ")? index: " << _value.index() << std::endl;
	return _value.index() == 5;
}

bool Literal::isIntegral() const
{
	std::cout << "isIntegral(" << *this << ")? index: " << _value.index() << std::endl;
	return isInt() || isInt64_t() || isUInt64_t() || isFloat() ;
}

const std::string& Literal::getString() const
{
   try
   {
      return std::get<std::string>(_value);
   }
   catch (std::bad_variant_access& exp)
   {
      std::cerr << "Called getString() of a TokenValue which holds " << *this << ". Index = " << _value.index() << std::endl << exp.what() << std::endl;
      assert(false && "Called getString() of non-string TokenValue");
   }
}

bool Literal::getBool() const
{
   try
   {
      return std::get<bool>(_value);
   }
   catch (std::bad_variant_access& exp)
   {
      std::cerr << "Called getBool() of a TokenValue which holds " << *this << ". Index = " << _value.index() << std::endl << exp.what() << std::endl;
      assert(false && "Called getBool() of non-bool TokenValue");
   }
}

int Literal::getInt() const
{
   try
   {
      return std::get<int>(_value);
   }
   catch (std::bad_variant_access& exp)
   {
      std::cerr << "Called getInt() of a TokenValue which holds " << *this << ". Index = " << _value.index() << std::endl << exp.what() << std::endl;
      assert(false && "Called getInt() of non-integer TokenValue");
   }
}

int64_t Literal::getInt64_t() const
{
   try
   {
      return std::get<int64_t>(_value);
   }
   catch (std::bad_variant_access& exp)
   {
      std::cerr << "Called getInt64_t() of a TokenValue which holds " << *this << ". Index = " << _value.index() << std::endl << exp.what() << std::endl;
      assert(false && "Called getInt64_t() of non-integer TokenValue");
   }
}

uint64_t Literal::getUInt64_t() const
{
   try
   {
      return std::get<uint64_t>(_value);
   }
   catch (std::bad_variant_access& exp)
   {
      std::cerr << "Called getUInt64_t() of a TokenValue which holds " << *this << ". Index = " << _value.index() << std::endl << exp.what() << std::endl;
      assert(false && "Called getUInt64_t() of non-integer TokenValue");
   }
}

float Literal::getFloat() const
{
   try
   {
      return std::get<float>(_value);
   }
   catch (std::bad_variant_access& exp)
   {
      std::cerr << "Called getFloat() of a TokenValue which holds " << *this << ". Index = " << _value.index() << std::endl << exp.what() << std::endl;
      assert(false && "Called getFloat() of non-float TokenValue");
   }
}

TokenIt TokenStream::emplace_back( TokenType type, const std::string& value )
{
	_tokens.emplace_back(type, std::move(Literal(value)));
	return --_tokens.end();
}

TokenIt TokenStream::emplace_back( TokenType type, bool b )
{
	_tokens.emplace_back(type, std::move(Literal(b)));
	return --_tokens.end();
}

TokenIt TokenStream::emplace_back( TokenType type, int i, const std::optional<std::string>& integral_formated_value/* = std::nullopt*/ )
{
	_tokens.emplace_back(type, std::move(Literal(i, integral_formated_value)));
	return --_tokens.end();
}

TokenIt TokenStream::emplace_back( TokenType type, int64_t i, const std::optional<std::string>& integral_formated_value/* = std::nullopt*/ )
{
	_tokens.emplace_back(type, std::move(Literal(i, integral_formated_value)));
	return --_tokens.end();
}

TokenIt TokenStream::emplace_back( TokenType type, uint64_t i, const std::optional<std::string>& integral_formated_value/* = std::nullopt*/ )
{
	_tokens.emplace_back(type, std::move(Literal(i, integral_formated_value)));
	return --_tokens.end();
}

TokenIt TokenStream::emplace_back( TokenType type, float i, const std::optional<std::string>& integral_formated_value/* = std::nullopt*/ )
{
	_tokens.emplace_back(type, std::move(Literal(i, integral_formated_value)));
	return --_tokens.end();
}

TokenIt TokenStream::emplace_back( TokenType type, const Literal& literal )
{
	_tokens.emplace_back(type, literal);
	return --_tokens.end();
}

TokenIt TokenStream::emplace_back( TokenType type, Literal&& literal )
{
	_tokens.emplace_back(type, std::move(literal));
	return --_tokens.end();
}

TokenIt TokenStream::push_back( const Token& t )
{
	_tokens.push_back(t);
	return --_tokens.end();
}

TokenIt TokenStream::push_back( Token&& t )
{
	_tokens.push_back(std::move(t));
	return --_tokens.end();
}

TokenIt TokenStream::insert( TokenIt before, TokenType type, const Literal& literal)
{
	return _tokens.insert(before, std::move(Token(type, literal)));
}

TokenIt TokenStream::insert( TokenIt before, TokenType type, Literal&& literal)
{
	return _tokens.insert(before, std::move(Token(type, std::move(literal))));
}

TokenIt TokenStream::begin()
{
	return _tokens.begin();
}

TokenIt TokenStream::end()
{
	return _tokens.end();
}

TokenIt TokenStream::find( TokenType type )
{
	return find(type, begin(), end());
}

TokenIt TokenStream::find( TokenType type, TokenIt from )
{
	return find(type, from, end());
}

TokenIt TokenStream::find( TokenType type, TokenIt from, TokenIt to )
{
	return std::find_if(
		from,
		to,
		[&type](const Token& t){ return t.getType() == type; }
	);
}

void TokenStream::clear()
{
	_tokens.clear();
}

}
