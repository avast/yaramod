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


std::string Token::getText(bool pure) const
{
	auto output = _value->getText(pure);
	if (_type == STRING_LENGTH)
	{
		assert(output != std::string());
		output[0] = '!';
	}
	else if (_type == STRING_OFFSET)
	{
		assert(output != std::string());
		output[0] = '@';
	}
	else if (_type == STRING_COUNT)
	{
		assert(output != std::string());
		output[0] = '#';
	}
	return output;
}

std::string Token::getPureText() const
{
	return getText(true);
}

const Literal& Token::getLiteral() const
{
	assert("Literal is not nullptr" && _value);
	return *_value;
}

const std::string& Token::getString() const
{
	assert(isString());
	return _value->getString();
}

bool Token::getBool() const
{
	assert(isBool()); 
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

Literal::ReferenceType Token::getLiteralReference() const
{
	return _value->getLiteralReference();
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
