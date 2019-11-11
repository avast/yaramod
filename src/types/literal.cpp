/**
 * @file src/types/literal.cpp
 * @brief Implementation of class Literal.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <algorithm>
#include <cassert>
#include <sstream>
#include <stack>

#include "yaramod/types/literal.h"
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
		std::cerr << "Called getString() of a TokenValue which holds " << *this << ". Index = " << _value.index() << std::endl << exp.what() << std::endl;
		throw YaramodError("Called getString() of non-string TokenValue");
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
		throw YaramodError("Called getBool() of non-bool TokenValue");
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
		throw YaramodError("Called getInt() of non-integer TokenValue");
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
		throw YaramodError("Called getInt64_t() of non-integer TokenValue");
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
		throw YaramodError("Called getUInt64_t() of non-integer TokenValue");
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
		std::cerr << "Called getDouble() of a TokenValue which holds " << *this << ". Index = " << _value.index() << std::endl << exp.what() << std::endl;
		throw YaramodError("Called getDouble() of non-double TokenValue");
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
		std::cerr << "Called getSymbol() of a TokenValue which holds " << *this << ". Index = " << _value.index() << std::endl << exp.what() << std::endl;
		throw YaramodError("Called getSymbol() of non-double TokenValue");
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
	std::cerr << "Unexpected index: '" << _value.index() << "'" << std::endl;
	std::cerr << "Value:" << *this << std::endl;
	assert(false);
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

TokenIt TokenStream::emplace_back(TokenType type, char value)
{
	_tokens.emplace_back(type, std::move(Literal(std::string() + value)));
	return --_tokens.end();
}

TokenIt TokenStream::emplace_back(TokenType type, const char* value, const std::optional<std::string>& formatted_value)
{
	_tokens.emplace_back(type, std::move(Literal(value, formatted_value)));
	return --_tokens.end();
}

TokenIt TokenStream::emplace_back(TokenType type, const std::string& value, const std::optional<std::string>& formatted_value)
{
	_tokens.emplace_back(type, std::move(Literal(value, formatted_value)));
	return --_tokens.end();
}

TokenIt TokenStream::emplace_back(TokenType type, std::string&& value, const std::optional<std::string>& formatted_value)
{
	_tokens.emplace_back(type, std::move(Literal(std::move(value), formatted_value)));
	return --_tokens.end();
}

TokenIt TokenStream::emplace_back(TokenType type, bool b, const std::optional<std::string>& formatted_value)
{
	_tokens.emplace_back(type, std::move(Literal(b, formatted_value)));
	return --_tokens.end();
}

TokenIt TokenStream::emplace_back(TokenType type, int i, const std::optional<std::string>& integral_formated_value/* = std::nullopt*/)
{
	_tokens.emplace_back(type, std::move(Literal(i, integral_formated_value)));
	return --_tokens.end();
}

TokenIt TokenStream::emplace_back(TokenType type, int64_t i, const std::optional<std::string>& integral_formated_value/* = std::nullopt*/)
{
	_tokens.emplace_back(type, std::move(Literal(i, integral_formated_value)));
	return --_tokens.end();
}

TokenIt TokenStream::emplace_back(TokenType type, uint64_t i, const std::optional<std::string>& integral_formated_value/* = std::nullopt*/)
{
	_tokens.emplace_back(type, std::move(Literal(i, integral_formated_value)));
	return --_tokens.end();
}

TokenIt TokenStream::emplace_back(TokenType type, double i, const std::optional<std::string>& integral_formated_value/* = std::nullopt*/)
{
	_tokens.emplace_back(type, std::move(Literal(i, integral_formated_value)));
	return --_tokens.end();
}

TokenIt TokenStream::emplace_back(TokenType type, const std::shared_ptr<Symbol>& s, const std::string& symbol_name)
{
	_tokens.emplace_back(type, std::move(Literal(s, symbol_name)));
	return --_tokens.end();
}

TokenIt TokenStream::emplace_back(TokenType type, std::shared_ptr<Symbol>&& s, const std::string& symbol_name)
{
	_tokens.emplace_back(type, std::move(Literal(std::move(s), symbol_name)));
	return --_tokens.end();
}

TokenIt TokenStream::emplace_back(TokenType type, const Literal& literal)
{
	_tokens.emplace_back(type, literal);
	return --_tokens.end();
}

TokenIt TokenStream::emplace_back(TokenType type, Literal&& literal)
{
	_tokens.emplace_back(type, std::move(literal));
	return --_tokens.end();
}

TokenIt TokenStream::emplace(const TokenIt& before, TokenType type, char value)
{
	_tokens.emplace(before, type, std::move(Literal(std::string() + value)));
	auto output = before;
	return --output;
}

TokenIt TokenStream::emplace(const TokenIt& before, TokenType type, const char* value)
{
	_tokens.emplace(before, type, std::move(Literal(value)));
	auto output = before;
	return --output;
}

TokenIt TokenStream::emplace(const TokenIt& before, TokenType type, const std::string& value)
{
	_tokens.emplace(before, type, std::move(Literal(value)));
	auto output = before;
	return --output;
}

TokenIt TokenStream::emplace(const TokenIt& before, TokenType type, std::string&& value)
{
	_tokens.emplace(before, type, std::move(Literal(std::move(value))));
	auto output = before;
	return --output;
}

TokenIt TokenStream::emplace(const TokenIt& before, TokenType type, bool b)
{
	_tokens.emplace(before, type, std::move(Literal(b)));
	auto output = before;
	return --output;
}

TokenIt TokenStream::emplace(const TokenIt& before, TokenType type, int i, const std::optional<std::string>& integral_formated_value/* = std::nullopt*/)
{
	_tokens.emplace(before, type, std::move(Literal(i, integral_formated_value)));
	auto output = before;
	return --output;
}

TokenIt TokenStream::emplace(const TokenIt& before, TokenType type, int64_t i, const std::optional<std::string>& integral_formated_value/* = std::nullopt*/)
{
	_tokens.emplace(before, type, std::move(Literal(i, integral_formated_value)));
	auto output = before;
	return --output;
}

TokenIt TokenStream::emplace(const TokenIt& before, TokenType type, uint64_t i, const std::optional<std::string>& integral_formated_value/* = std::nullopt*/)
{
	_tokens.emplace(before, type, std::move(Literal(i, integral_formated_value)));
	auto output = before;
	return --output;
}

TokenIt TokenStream::emplace(const TokenIt& before, TokenType type, double i, const std::optional<std::string>& integral_formated_value/* = std::nullopt*/)
{
	_tokens.emplace(before, type, std::move(Literal(i, integral_formated_value)));
	auto output = before;
	return --output;
}

TokenIt TokenStream::emplace(const TokenIt& before, TokenType type, const std::shared_ptr<Symbol>& s, const std::string& symbol_name)
{
	_tokens.emplace(before, type, std::move(Literal(s, symbol_name)));
	auto output = before;
	return --output;
}

TokenIt TokenStream::emplace(const TokenIt& before, TokenType type, std::shared_ptr<Symbol>&& s, const std::string& symbol_name)
{
	_tokens.emplace(before, type, std::move(Literal(std::move(s), symbol_name)));
	auto output = before;
	return --output;
}

TokenIt TokenStream::emplace(const TokenIt& before, TokenType type, const Literal& literal)
{
	_tokens.emplace(before, type, literal);
	auto output = before;
	return --output;
}

TokenIt TokenStream::emplace(const TokenIt& before, TokenType type, Literal&& literal)
{
	_tokens.emplace(before, type, std::move(literal));
	auto output = before;
	return --output;
}

TokenIt TokenStream::push_back(const Token& t)
{
	_tokens.push_back(t);
	return --_tokens.end();
}

TokenIt TokenStream::push_back(Token&& t)
{
	_tokens.push_back(std::move(t));
	return --_tokens.end();
}

TokenIt TokenStream::insert(TokenIt before, TokenType type, const Literal& literal)
{
	return _tokens.insert(before, std::move(Token(type, literal)));
}

TokenIt TokenStream::insert(TokenIt before, TokenType type, Literal&& literal)
{
	return _tokens.insert(before, std::move(Token(type, std::move(literal))));
}

TokenIt TokenStream::erase(TokenIt element)
{
	return _tokens.erase(element);
}

TokenIt TokenStream::erase(TokenIt first, TokenIt last)
{
	return _tokens.erase(first, last);
}

void TokenStream::move_append(TokenStream* donor)
{
	_tokens.splice(_tokens.end(), donor->_tokens);
}

void TokenStream::move_append(TokenStream* donor, TokenIt before)
{
	_tokens.splice(before, donor->_tokens);
}

TokenIt TokenStream::begin()
{
	return _tokens.begin();
}

TokenIt TokenStream::end()
{
	return _tokens.end();
}

TokenConstIt TokenStream::begin() const
{
	return _tokens.begin();
}

TokenConstIt TokenStream::end() const
{
	return _tokens.end();
}

std::reverse_iterator<TokenIt> TokenStream::rbegin()
{
	return _tokens.rbegin();
}

std::reverse_iterator<TokenIt> TokenStream::rend()
{
	return _tokens.rend();
}

std::reverse_iterator<TokenConstIt> TokenStream::rbegin() const
{
	return _tokens.rbegin();
}

std::reverse_iterator<TokenConstIt> TokenStream::rend() const
{
	return _tokens.rend();
}

std::optional<TokenIt> TokenStream::predecessor(TokenIt it)
{
	if(it == begin())
		return std::nullopt;
	else
		return std::prev(it);
}

size_t TokenStream::size() const
{
	return _tokens.size();
}

bool TokenStream::empty() const
{
	return _tokens.empty();
}

TokenIt TokenStream::find(TokenType type)
{
	return find(type, begin(), end());
}

TokenIt TokenStream::find(TokenType type, TokenIt from)
{
	return find(type, from, end());
}

TokenIt TokenStream::find(TokenType type, TokenIt from, TokenIt to)
{
	return std::find_if(
		from,
		to,
		[&type](const Token& t){ return t.getType() == type; }
	);
}

TokenIt TokenStream::findBackwards(TokenType type)
{
	return findBackwards(type, begin(), end());
}

TokenIt TokenStream::findBackwards(TokenType type, TokenIt to)
{
	return findBackwards(type, begin(), to);
}

TokenIt TokenStream::findBackwards(TokenType type, TokenIt from, TokenIt to)
{
	if(from == to)
		return to;
	for(TokenIt it = to; --it != from;)
	{
		if(it->getType() == type)
			return it;
	}
	if(from->getType() == type)
		return from;
	else
		return to;
}

std::vector<std::string> TokenStream::getTokensAsText() const
{
	std::vector<std::string> output;
	for(auto t : _tokens)
	{
		output.push_back(t.getPureText());
	}
	return output;
}

void TokenStream::clear()
{
	_tokens.clear();
}


class LeftBracketEntry {
public:
	LeftBracketEntry(size_t line, size_t tabulator, bool put_new_lines) : _put_new_lines(put_new_lines), _tabulator(tabulator), _line(line) {}

	size_t getLine() const { return _line; }
	size_t getTabulator() const { return _tabulator; }
	bool putNewLines() const { return _put_new_lines; }
private:
	bool _put_new_lines;
	size_t _tabulator;
	size_t _line;
};


class BracketStack {
public:
	void addLeftBracket(size_t line, bool put_new_lines)
	{

		if(_brackets.empty())
			_brackets.emplace_back(line, 1, put_new_lines);
		else
		{
			const auto& previous = _brackets.back();
			size_t tabulator = previous.getTabulator();
			if(line != previous.getLine())
				++tabulator;
			_brackets.emplace_back(line, tabulator, put_new_lines);
		}
	}

	void addRightBracket()
	{
		assert(!_brackets.empty());
		_brackets.pop_back();
	}

	/// @name Observe methods
	/// @{
	bool putNewlineInCurrentSector() const
	{
		if(_brackets.empty())
			return false;
		return _brackets.back().putNewLines();
	}

	std::string getTabulators() const
	{
		if(_brackets.empty())
			return std::string{};
		return std::string(_brackets.back().getTabulator(), '\t');
	}
	/// @}

	friend std::ostream& operator<<(std::ostream& os, const BracketStack& stack) {
		os << "Stack:" << std::endl;
		for(const auto& entry : stack._brackets)
			os << "(line: " << entry.getLine() << ", tabulator: " << entry.getTabulator() << ")" << std::endl;
		return os;
	}
private:
	std::vector<LeftBracketEntry> _brackets;
};


void TokenStream::determineNewlineSectors()
{
	std::stack<TokenIt> leftBrackets;
	for(auto it = begin(); it != end(); ++it)
	{
		auto current = it->getType();
		if(current == LP || current == LP_ENUMERATION || current == HEX_JUMP_LEFT_BRACKET || current == REGEXP_START_SLASH || current == HEX_START_BRACKET || current == LP_WITH_SPACE_AFTER || current == LP_WITH_SPACES)
			leftBrackets.push(it);
		else if(current == RP || current == RP_ENUMERATION || current == HEX_JUMP_RIGHT_BRACKET || current == REGEXP_END_SLASH || current == HEX_END_BRACKET || current == RP_WITH_SPACE_BEFORE || current == RP_WITH_SPACES)
		{
			if(leftBrackets.top()->getFlag()) // the '(' corresponding to the current ')' has new-line sector. Therefore we set this token flag too.
				it->setFlag(true);
			leftBrackets.pop();
		}
		else if(current == NEW_LINE && !leftBrackets.empty())
			leftBrackets.top()->setFlag(true);
	}
}

void TokenStream::addMissingNewLines()
{
	BracketStack brackets;
	size_t lineCounter = 0;
	for(auto it = begin(); it != end(); ++it)
	{
		auto current = it->getType();
		auto nextIt = std::next(it);
		if(nextIt == end())
			 break;
		auto next = nextIt->getType();
		if(current == LP || current == LP_ENUMERATION || current == HEX_JUMP_LEFT_BRACKET || current == REGEXP_START_SLASH || current == HEX_START_BRACKET || current == LP_WITH_SPACE_AFTER || current == LP_WITH_SPACES)
		{
			brackets.addLeftBracket(lineCounter, it->getFlag());
			if(brackets.putNewlineInCurrentSector() && next != NEW_LINE && next != ONELINE_COMMENT && next != COMMENT)
			{
				nextIt = emplace(nextIt, TokenType::NEW_LINE, "\n");
				next = nextIt->getType();
			}
		}
		if(next == RP || next == RP_ENUMERATION || next == HEX_JUMP_RIGHT_BRACKET || next == REGEXP_END_SLASH || next == HEX_END_BRACKET || next == RP_WITH_SPACE_BEFORE || next == RP_WITH_SPACES)
		{
			if(brackets.putNewlineInCurrentSector() && current != NEW_LINE)
			{
				nextIt = emplace(nextIt, TokenType::NEW_LINE, "\n");
				next = nextIt->getType();
			}
			else
				brackets.addRightBracket();
		}
		if(current == NEW_LINE)
			++lineCounter;
	}
}

void TokenStream::autoformat()
{
	determineNewlineSectors();
	addMissingNewLines();
	formatted = true;
}

size_t TokenStream::PrintHelper::insertIntoStream(std::stringstream* ss, char what)
{
	columnCounter += 1;
	if(ss)
		*ss << what;
	return columnCounter;
}

size_t TokenStream::PrintHelper::insertIntoStream(std::stringstream* ss, const std::string& what, size_t length)
{
	if(length != 0)
		columnCounter += length;
	else
		columnCounter += what.length();
	if(ss)
		*ss << what;
	return columnCounter;
}

// NEW_LINE, returns current column
size_t TokenStream::PrintHelper::insertIntoStream(std::stringstream* ss, TokenStream* ts, TokenIt what)
{
	std::stringstream tmp;
	tmp << *what;
	const std::string& appendee = tmp.str();
	assert(what->getType() != ONELINE_COMMENT);
	auto prevIt = ts->predecessor(what);
	if(what->getType() == NEW_LINE)
	{
		if(!commentOnThisLine || (prevIt && (*prevIt)->getType() == COLON))
		{
			if(commentPool.size() >= 2)
				for(auto comment : commentPool)
					comment->setIndentation(maximalCommentColumn);
			commentPool.clear();
			maximalCommentColumn = 0;
		}
		++lineCounter;
		commentOnThisLine = false;
		columnCounter = 0;
	}
	else
	{
		columnCounter += appendee.length();
		if(columnCounter > maximalCommentColumn)
			maximalCommentColumn = columnCounter;
	}

	if(ss)
		*ss << appendee;
	return columnCounter;
}

size_t TokenStream::PrintHelper::printComment(std::stringstream* ss, TokenStream* ts, TokenIt it, bool alignComment)
{
	auto prevIt = ts->predecessor(it);

	const std::string& indent = it->getLiteral().getFormattedValue();
	// print indent part 1
	if(prevIt && (*prevIt)->getType() == NEW_LINE)
	{
		if(ss)
			*ss << indent;
	}// print indent part 2
	else if(ss && alignComment && columnCounter < it->getIndentation() && (!prevIt || (*prevIt)->getType() != COLON))
		*ss << std::string(it->getIndentation() - columnCounter + 1, ' ');
	// remember oneline comments
	if(it->getType() == ONELINE_COMMENT && (!prevIt || (*prevIt)->getType() != COLON))
	{
		commentOnThisLine = true;
		commentPool.push_back(it);
	}

	if(ss)
		for(const auto& c : it->getPureText())
			*ss << c;
	return columnCounter;
}

std::string TokenStream::getText(bool withIncludes, bool alignComments)
{
	PrintHelper helper;
	if(alignComments)
		getTextProcedure(helper, nullptr, withIncludes, alignComments); // First call determines alignment of comments

	std::stringstream os;
	getTextProcedure(helper, &os, withIncludes, alignComments); // Second call constructs the text
	return os.str();
}

void TokenStream::getTextProcedure(PrintHelper& helper, std::stringstream* os, bool withIncludes, bool alignComments)
{
	if(!formatted)
		autoformat();
	BracketStack brackets;
	int current_line_tabs = 0;
	bool inside_rule = false;
	bool inside_hex_string = false;
	bool inside_hex_jump = false;
	bool inside_regexp = false;
	bool inside_enumeration_brackets = false;
	bool second_nibble = true;
	for(auto it = begin(); it != end(); ++it)
	{
		auto current = it->getType();

		if(current == INCLUDE_DIRECTIVE && withIncludes)
			continue;
		else if(current == INCLUDE_PATH)
		{
			assert(it->isIncludeToken());
			if(withIncludes)
			{
				const std::string& text = it->getSubTokenStream()->getText(withIncludes);
				helper.insertIntoStream(os, text);
				continue;
			}
			else
				helper.insertIntoStream(os, this, it);
		}
		else if((current == ONELINE_COMMENT || current == COMMENT))
			helper.printComment(os, this, it, alignComments);
		else
			helper.insertIntoStream(os, this, it);

		auto nextIt = std::next(it);
		if(nextIt == end())
			 break;
		auto next = nextIt->getType();
		if(current == RULE_BEGIN)
			inside_rule = true;
		else if(current == RULE_END)
			inside_rule = false;
		else if(current == HEX_START_BRACKET)
			inside_hex_string = true;
		else if(current == HEX_END_BRACKET)
			inside_hex_string = false;
		else if(current == HEX_JUMP_LEFT_BRACKET)
			inside_hex_jump = true;
		else if(current == HEX_JUMP_RIGHT_BRACKET)
			inside_hex_jump = false;
		else if(current == REGEXP_START_SLASH)
			inside_regexp = true;
		else if(current == REGEXP_END_SLASH)
			inside_regexp = false;
		else if(current == LP_ENUMERATION)
			inside_enumeration_brackets = true;
		else if(current == RP_ENUMERATION)
			inside_enumeration_brackets = false;

		if(it->isLeftBracket())
		{
			brackets.addLeftBracket(helper.getCurrentLine(), it->getFlag());
			if(it->getFlag())
				++current_line_tabs;
		}
		if(it->isRightBracket())
		{
			brackets.addRightBracket();
		}
		if(current == NEW_LINE)
		{
			if(inside_rule && next != ONELINE_COMMENT && next != COMMENT && next != NEW_LINE)
			{
				if(next == META
					|| next == STRINGS
					|| next == CONDITION)
				{
					helper.insertIntoStream(os, "\t", TABULATOR_LENGTH);
				}
				else if(next != RULE_END)
				{
					if(nextIt->isRightBracket() && nextIt->getFlag())
						--current_line_tabs;
					helper.insertIntoStream(os, std::string(2 + current_line_tabs, '\t'), (2 + current_line_tabs) * TABULATOR_LENGTH);
				}
			}
		}
		else if(inside_hex_string)
		{
			switch(current)
			{
				case HEX_NIBBLE:
				case HEX_WILDCARD_LOW:
				case HEX_WILDCARD_HIGH:
					second_nibble = !second_nibble;
					break;
				case HEX_ALT:
				case HEX_JUMP_FIXED:
				case HEX_JUMP_RIGHT_BRACKET:
				case HEX_START_BRACKET:
					second_nibble = true;
					break;
				default:
					break;
			}
			if(!inside_hex_jump && next != NEW_LINE)
			{
				if(second_nibble && next != COMMA)
					helper.insertIntoStream(os, ' ');
			}
		}
		else if(!inside_regexp && !inside_enumeration_brackets)
		{
			switch(current)
			{
				case META:
				case STRINGS:
				case CONDITION:
				case UNARY_MINUS:
				case BITWISE_NOT:
				case INTEGER_FUNCTION:
				case FUNCTION_SYMBOL:
				case ARRAY_SYMBOL:
				case LSQB:
				case DOT:
				case FUNCTION_CALL_LP:
					break;
				case LP:
					if(next == COMMENT || next == ONELINE_COMMENT)
						helper.insertIntoStream(os, ' ');
					break;
				default:
					switch(next)
					{
						case RP:
						case RSQB:
						case DOT:
						case NEW_LINE:
						case COMMA:
						case LSQB:
						case FUNCTION_CALL_LP:
						case FUNCTION_CALL_RP:
							break;
						case REGEXP_MODIFIERS:
							if(current != REGEXP_MODIFIERS)
								break;
							[[fallthrough]];
						default:
							if(next != LSQB || (current != STRING_OFFSET && current != STRING_LENGTH))
								helper.insertIntoStream(os, ' ');
					}
			}
		}
		else if(inside_enumeration_brackets)
		{
			if(current != LP_ENUMERATION && next != RP_ENUMERATION && next != COMMA)
				helper.insertIntoStream(os, ' ');
		}
		else if(current == HEX_ALT_RIGHT_BRACKET || current == HEX_ALT_LEFT_BRACKET)
			helper.insertIntoStream(os, ' ');
	}
}

} //namespace yaramod
