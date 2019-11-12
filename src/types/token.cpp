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
	if (is<std::string>())
	{
		const std::string& output = get<std::string>();
		if (pure)
			return unescapeString(output);
		else
			return '"' + output + '"';
	}
	else if (is<bool>())
	{
		if (_formated_value.has_value())
			return _formated_value.value();
		std::ostringstream ss;
		ss << std::boolalpha << get<bool>();
		return ss.str();
	}
	else if (is<int>())
	{
		if (_formated_value.has_value())
			return _formated_value.value();
		else
			return numToStr<int>(get<int>());
	}
	else if (is<int64_t>())
	{
		if (_formated_value.has_value())
			return _formated_value.value();
		else
			return numToStr<int64_t>(get<int64_t>());
	}
	else if (is<uint64_t>())
	{
		if (_formated_value.has_value())
			return _formated_value.value();
		else
			return numToStr<uint64_t>(get<uint64_t>());
	}
	else if (is<double>())
	{
		if (_formated_value.has_value())
			return _formated_value.value();
		else
			return numToStr<double>(get<double>());
	}
	else if (is<std::shared_ptr<Symbol>>())
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

bool Literal::isIntegral() const
{
	return is<int>() ||  is<int64_t>() || is<uint64_t>() || is<double>() ;
}

const Literal& Token::getLiteral() const
{
	assert(_value);
	return *_value;
}

const std::string& Token::getString() const
{
	return _value->get<std::string>();
}

bool Token::getBool() const
{
	return _value->get<bool>();
}

int Token::getInt() const
{
	return _value->get<int>();
}

int64_t Token::getInt64_t() const
{
	return _value->get<int64_t>();
}

uint64_t Token::getUInt64_t() const
{
	return _value->get<uint64_t>();
}

double Token::getDouble() const
{
	return _value->get<double>();
}

const std::shared_ptr<Symbol>& Token::getSymbol() const
{
	return _value->get<std::shared_ptr<Symbol>>();
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
