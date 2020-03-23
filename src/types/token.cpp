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
	assert("Literal is not nullptr" && _value);
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

std::int64_t Token::getInt() const
{
	return _value->getInt();
}

std::uint64_t Token::getUInt() const
{
	return _value->getUInt();
}

double Token::getFloat() const
{
	return _value->getFloat();
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
