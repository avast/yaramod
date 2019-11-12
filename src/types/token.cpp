/**
 * @file src/types/token.cpp
 * @brief Implementation of class Literal.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <algorithm>
#include <cassert>
#include <sstream>
#include <stack>

#include "yaramod/types/token.h"
#include "yaramod/types/tokenstream.h"
#include "yaramod/utils/utils.h"

namespace yaramod {

#define TABULATOR_LENGTH 8

/**
 * Constructor.
 *
 * @param value String value of the literal.
 * @param formated_value formatted value of the literal.
 */
Literal::Literal(const std::string& value, const std::optional<std::string>& formated_value/* = std::nullopt*/)
	: _value(value)
	, _formated_value(formated_value)
{
}

/**
 * Constructor.
 *
 * @param value String value of the literal.
 * @param formated_value formatted value of the literal.
 */
Literal::Literal(const char* value, const std::optional<std::string>& formated_value/* = std::nullopt*/)
	: _value(std::string(value))
	, _formated_value(formated_value)
{
}

/**
 * Constructor.
 *
 * @param value String value of the literal.
 * @param formated_value formatted value of the literal.
 */
Literal::Literal(std::string&& value, const std::optional<std::string>& formated_value/* = std::nullopt*/)
	: _value(std::move(value))
	, _formated_value(formated_value)
{
}

/**
 * Constructor.
 *
 * @param value Bool value of the literal.
 */
Literal::Literal(bool value, const std::optional<std::string>& formated_value/* = std::nullopt*/)
	: _value(value)
	, _formated_value(formated_value)
{
}

/**
 * Constructor.
 *
 * @param value integral value of the literal.
 * @param integral_formated_value formatted value of the integral literal.
 */
Literal::Literal(int value, const std::optional<std::string>& integral_formated_value/* = std::nullopt*/)
	: _value(value)
	, _formated_value(integral_formated_value)
{
}

/**
 * Constructor.
 *
 * @param value integral value of the literal.
 * @param integral_formated_value formatted value of the integral literal.
 */
Literal::Literal(int64_t value, const std::optional<std::string>& integral_formated_value/* = std::nullopt*/)
	: _value(value)
	, _formated_value(integral_formated_value)
{
}

/**
 * Constructor.
 *
 * @param value integral value of the literal.
 * @param integral_formated_value formatted value of the integral literal.
 */
Literal::Literal(uint64_t value, const std::optional<std::string>& integral_formated_value/* = std::nullopt*/)
	: _value(value)
	, _formated_value(integral_formated_value)
{
}

/**
 * Constructor.
 *
 * @param value integral value of the literal.
 * @param integral_formated_value formatted value of the integral literal.
 */
Literal::Literal(double value, const std::optional< std::string >& integral_formated_value/*= std::nullopt*/)
	: _value(value)
	, _formated_value(integral_formated_value)
{
}

/**
 * Constructor.
 *
 * @param value Symbol value of the literal.
 * @param name formatted value of the literal.
 */
Literal::Literal(const std::shared_ptr<Symbol>& value, const std::string& name)
	: _value(value)
	, _formated_value(name)
{
}

/**
 * Constructor.
 *
 * @param value Symbol value of the literal.
 * @param name formatted value of the literal.
 */
Literal::Literal(std::shared_ptr<Symbol>&& value, const std::string& name)
	: _value(std::move(value))
	, _formated_value(name)
{
}

/**
 * Setter methods
 *
 */
void Literal::setValue(const std::string& s)
{
	_value = s;
}

void Literal::setValue(std::string&& s)
{
	_value = std::move(s);
}

void Literal::setValue(bool b)
{
	_value = b;
}

void Literal::setValue(int i, const std::optional<std::string>& integral_formated_value/*= std::nullopt*/)
{
	_value = i;
	_formated_value = integral_formated_value;
}

void Literal::setValue(int64_t i, const std::optional<std::string>& integral_formated_value/*= std::nullopt*/)
{
	_value = i;
	_formated_value = integral_formated_value;
}

void Literal::setValue(uint64_t i, const std::optional<std::string>& integral_formated_value/*= std::nullopt*/)
{
	_value = i;
	_formated_value = integral_formated_value;
}

void Literal::setValue(double f, const std::optional<std::string>& integral_formated_value/*= std::nullopt*/)
{
	_value = f;
	_formated_value = integral_formated_value;
}


void Literal::setValue(const std::shared_ptr<Symbol>& s, const std::string& symbol_name)
{
	_value = s;
	_formated_value = symbol_name;
}
void Literal::setValue(std::shared_ptr<Symbol>&& s, std::string&& symbol_name)
{
	_value = std::move(s);
	_formated_value = std::move(symbol_name);
}

/**
 * Getter methods
 *
 */
const std::string& Literal::getString() const
{
	try
	{
		return std::get<std::string>(_value);
	}
	catch (std::bad_variant_access& exp)
	{
		std::stringstream err;
		err << "Called getString() of a non-string TokenValue, which holds '" << *this << "'. Actual variant index is " << _value.index() << "." << std::endl << exp.what() << std::endl;
		throw YaramodError(err.str());
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
		std::stringstream err;
		err << "Called getBool() of a non-bool TokenValue, which holds '" << *this << "'. Actual variant index is " << _value.index() << "." << std::endl << exp.what() << std::endl;
		throw YaramodError(err.str());
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
		std::stringstream err;
		err << "Called getInt() of a TokenValue, which holds '" << *this << "'. Actual variant index is " << _value.index() << "." << std::endl << exp.what() << std::endl;
		throw YaramodError(err.str());
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
		std::stringstream err;
		err << "Called getInt64_t() of a TokenValue, which holds '" << *this << "'. Actual variant index is " << _value.index() << "." << std::endl << exp.what() << std::endl;
		throw YaramodError(err.str());
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
		std::stringstream err;
		err << "Called getUInt64_t() of a TokenValue, which holds '" << *this << "'. Actual variant index is " << _value.index() << "." << std::endl << exp.what() << std::endl;
		throw YaramodError(err.str());
	}
}

double Literal::getDouble() const
{
	try
	{
		return std::get<double>(_value);
	}
	catch (std::bad_variant_access& exp)
	{
		std::stringstream err;
		err << "Called getDouble() of a TokenValue, which holds '" << *this << "'. Actual variant index is " << _value.index() << "." << std::endl << exp.what() << std::endl;
		throw YaramodError(err.str());
	}
}

const std::shared_ptr<Symbol>& Literal::getSymbol() const
{
	try
	{
		return std::get<std::shared_ptr<Symbol>>(_value);
	}
	catch (std::bad_variant_access& exp)
	{
		std::stringstream err;
		err << "Called getSymbol() of a TokenValue, which holds '" << *this << "'. Actual variant index is " << _value.index() << "." << std::endl << exp.what() << std::endl;
		throw YaramodError(err.str());
	}
}

std::string Literal::getFormattedValue() const
{
	return _formated_value.value_or(std::string());
}

/**
 * Returns the string representation of the literal in the form it was created in, enclosed in double quotes.
 *
 * @return String representation.
 */
std::string Literal::getText(bool pure) const
{
	if (isString())
	{
		const std::string& output = getString();
		if(pure)
			return unescapeString(output);
		else
			return '"' + output + '"';
	}
	else if (isBool())
	{
		if(_formated_value.has_value())
			return _formated_value.value();
		std::ostringstream ss;
		ss << std::boolalpha << getBool();
		return ss.str();
	}
	else if (isInt())
	{
		if(_formated_value.has_value())
			return _formated_value.value();
		else
			return numToStr<int>(getInt());
	}
	else if (isInt64_t())
	{
		if(_formated_value.has_value())
			return _formated_value.value();
		else
			return numToStr<int64_t>(getInt64_t());
	}
	else if (isUInt64_t())
	{
		if(_formated_value.has_value())
			return _formated_value.value();
		else
			return numToStr<uint64_t>(getUInt64_t());
	}
	else if (isDouble())
	{
		if(_formated_value.has_value())
			return _formated_value.value();
		else
			return numToStr<double>(getDouble());
	}
	else if (isSymbol())
	{
		assert(_formated_value);
		return _formated_value.value();
	}
	else
	{
		std::stringstream err;
		err << "Error: Unexpected index of TokenValue class '" << *this << "'. Index: " << _value.index() << std::endl;
		throw YaramodError(err.str());
	}
	return std::string();
}

/**
 * Returns the string representation readable, so instead of '\x40' prints '@', instead of '\x0a' or '\n' prints new line.
 *
 * @return String representation.
 */
std::string Literal::getPureText() const
{
	return getText(true);
}

bool Literal::isString() const
{
	return _value.index() == 0;
}

bool Literal::isBool() const
{
	return _value.index() == 1;
}

bool Literal::isInt() const
{
	return _value.index() == 2;
}

bool Literal::isInt64_t() const
{
	return _value.index() == 3;
}

bool Literal::isUInt64_t() const
{
	return _value.index() == 4;
}

bool Literal::isDouble() const
{
	return _value.index() == 5;
}

bool Literal::isSymbol() const
{
	return _value.index() == 6;
}

bool Literal::isIntegral() const
{
	return isInt() ||  isInt64_t() || isUInt64_t() || isDouble() ;
}

const Literal& Token::getLiteral() const
{
	assert(_value);
	return *_value;
}

const std::string& Token::getString() const
{
	return _value->getString();
}

bool Token::getBool() const
{
	return _value->getBool();
}

int Token::getInt() const
{
	return _value->getInt();
}

int64_t Token::getInt64_t() const
{
	return _value->getInt64_t();
}

uint64_t Token::getUInt64_t() const
{
	return _value->getUInt64_t();
}

double Token::getDouble() const
{
	return _value->getDouble();
}

const std::shared_ptr<Symbol>& Token::getSymbol() const
{
	return _value->getSymbol();
}

const std::shared_ptr<TokenStream>& Token::getSubTokenStream() const
{
	return _subTokenStream;
}

const std::shared_ptr<TokenStream>& Token::initializeSubTokenStream()
{
	assert(_subTokenStream == nullptr);
	_subTokenStream = std::make_shared<TokenStream>();
	return getSubTokenStream();
}

} //namespace yaramod
