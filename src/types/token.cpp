/**
 * @file src/types/token.cpp
 * @brief Implementation of class Token.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <algorithm>
#include <cassert>
#include <sstream>
#include <stack>

#include "yaramod/types/token.h"
#include "yaramod/types/token_stream.h"

namespace yaramod {

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

int64_t Token::getInt64() const
{
	return _value->get<int64_t>();
}

uint64_t Token::getUInt64() const
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
