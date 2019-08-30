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

/**
 * Constructor.
 *
 * @param value String value of the literal.
 * @param formated_value formatted value of the literal.
 */
Literal::Literal(const std::string& value, const std::optional<std::string>& formated_value/* = std::nullopt*/ )
	: _value(value)
   , _formated_value( formated_value )
{
}

/**
 * Constructor.
 *
 * @param value String value of the literal.
 * @param formated_value formatted value of the literal.
 */
Literal::Literal(const char* value, const std::optional<std::string>& formated_value/* = std::nullopt*/ )
	: _value(std::string(value))
   , _formated_value( formated_value )
{
}

/**
 * Constructor.
 *
 * @param value String value of the literal.
 * @param formated_value formatted value of the literal.
 */
Literal::Literal(std::string&& value, const std::optional<std::string>& formated_value/* = std::nullopt*/ )
   : _value(std::move(value))
   , _formated_value( formated_value )
{
}

/**
 * Constructor.
 *
 * @param value Bool value of the literal.
 */
Literal::Literal( bool value, const std::optional<std::string>& formated_value/* = std::nullopt*/ )
	: _value( value )
   , _formated_value( formated_value )
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
   , _formated_value( integral_formated_value )
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
   , _formated_value( integral_formated_value )
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
   , _formated_value( integral_formated_value )
{
}

/**
 * Constructor.
 *
 * @param value integral value of the literal.
 * @param integral_formated_value formatted value of the integral literal.
 */
Literal::Literal( double value, const std::optional< std::string >& integral_formated_value /*= std::nullopt*/ )
   : _value( value )
   , _formated_value( integral_formated_value )
{
}

/**
 * Constructor.
 *
 * @param value Symbol value of the literal.
 * @param name formatted value of the literal.
 */
Literal::Literal( const std::shared_ptr<Symbol>& value, const std::string& name )
   : _value( value )
   , _formated_value(name)
{
}

/**
 * Constructor.
 *
 * @param value Symbol value of the literal.
 * @param name formatted value of the literal.
 */
Literal::Literal( std::shared_ptr<Symbol>&& value, const std::string& name )
   : _value( std::move(value) )
   , _formated_value(name)
{
}

/**
 * Setter methods
 *
 */
void Literal::setValue( const std::string& s )
{
	_value = s;
}

void Literal::setValue( std::string&& s )
{
	_value = std::move(s);
}

void Literal::setValue( bool b )
{
	_value = b;
}

void Literal::setValue( int i, const std::optional<std::string>& integral_formated_value /*= std::nullopt*/ )
{
	_value = i;
	_formated_value = integral_formated_value;
}

void Literal::setValue( int64_t i, const std::optional<std::string>& integral_formated_value /*= std::nullopt*/ )
{
	_value = i;
	_formated_value = integral_formated_value;
}

void Literal::setValue( uint64_t i, const std::optional<std::string>& integral_formated_value /*= std::nullopt*/ )
{
	_value = i;
	_formated_value = integral_formated_value;
}

void Literal::setValue( double f, const std::optional<std::string>& integral_formated_value /*= std::nullopt*/ )
{
	_value = f;
	_formated_value = integral_formated_value;
}


void Literal::setValue( const std::shared_ptr<Symbol>& s, const std::string& symbol_name )
{
	_value = s;
	_formated_value = symbol_name;
}
void Literal::setValue( std::shared_ptr<Symbol>&& s, std::string&& symbol_name )
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

double Literal::getDouble() const
{
   try
   {
      return std::get<double>(_value);
   }
   catch (std::bad_variant_access& exp)
   {
      std::cerr << "Called getDouble() of a TokenValue which holds " << *this << ". Index = " << _value.index() << std::endl << exp.what() << std::endl;
      assert(false && "Called getDouble() of non-double TokenValue");
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
      assert(false && "Called getSymbol() of non-double TokenValue");
   }
}

std::string Literal::getFormattedValue() const
{
   return _formated_value.value_or(std::string());
}

/**
 * Returns the string representation of the literal.
 *
 * @return String representation.
 */
std::string Literal::getText( bool pure /*= false*/ ) const
{
	if (isString())
	{
		const std::string& output = getString();
		if(pure || output == "")
			return output;
		else
			return '"' + escapeString(output) + '"';
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
			return numToStr<int>( getInt() );
	}
	else if (isInt64_t())
	{
		if(_formated_value.has_value())
			return _formated_value.value();
		else
			return numToStr<int64_t>( getInt64_t() );
	}
	else if (isUInt64_t())
	{
		if(_formated_value.has_value())
			return _formated_value.value();
		else
			return numToStr<uint64_t>( getUInt64_t() );
	}
	else if (isDouble())
	{
		if(_formated_value.has_value())
			return _formated_value.value();
		else
			return numToStr<double>( getDouble() );
	}
	else if (isSymbol())
	{
		assert(_formated_value);
		return _formated_value.value();
	}
	std::cerr << "Unexpected index: '" << _value.index() << "'"<< std::endl;
	std::cerr << "Value:" << *this << std::endl;
	assert(false);
   return std::string();
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
	// return std::is_same_v< decltype(_value), std::string& >;
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

TokenIt TokenStream::emplace_back( TokenType type, char value )
{
	_tokens.emplace_back(type, std::move(Literal(std::string() + value)));
	return --_tokens.end();
}

TokenIt TokenStream::emplace_back( TokenType type, const char* value, const std::optional<std::string>& formatted_value )
{
	_tokens.emplace_back(type, std::move(Literal(value, formatted_value)));
	return --_tokens.end();
}

TokenIt TokenStream::emplace_back( TokenType type, const std::string& value, const std::optional<std::string>& formatted_value )
{
	_tokens.emplace_back(type, std::move(Literal(value, formatted_value)));
	return --_tokens.end();
}

TokenIt TokenStream::emplace_back( TokenType type, std::string&& value, const std::optional<std::string>& formatted_value )
{
	_tokens.emplace_back(type, std::move(Literal(std::move(value), formatted_value)));
	return --_tokens.end();
}

TokenIt TokenStream::emplace_back( TokenType type, bool b, const std::optional<std::string>& formatted_value )
{
	_tokens.emplace_back(type, std::move(Literal(b, formatted_value)));
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

TokenIt TokenStream::emplace_back( TokenType type, double i, const std::optional<std::string>& integral_formated_value/* = std::nullopt*/ )
{
	_tokens.emplace_back(type, std::move(Literal(i, integral_formated_value)));
	return --_tokens.end();
}

TokenIt TokenStream::emplace_back( TokenType type, const std::shared_ptr<Symbol>& s, const std::string& symbol_name )
{
	_tokens.emplace_back(type, std::move(Literal(s, symbol_name)));
	return --_tokens.end();
}

TokenIt TokenStream::emplace_back( TokenType type, std::shared_ptr<Symbol>&& s, const std::string& symbol_name )
{
	_tokens.emplace_back(type, std::move(Literal(std::move(s), symbol_name)));
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

TokenIt TokenStream::emplace( const TokenIt& before, TokenType type, char value )
{
	_tokens.emplace(before, type, std::move(Literal(std::string() + value)));
	auto output = before;
	return --output;
}

TokenIt TokenStream::emplace( const TokenIt& before, TokenType type, const char* value )
{
	_tokens.emplace(before, type, std::move(Literal(value)));
	auto output = before;
	return --output;
}

TokenIt TokenStream::emplace( const TokenIt& before, TokenType type, const std::string& value )
{
	_tokens.emplace(before, type, std::move(Literal(value)));
	auto output = before;
	return --output;
}

TokenIt TokenStream::emplace( const TokenIt& before, TokenType type, std::string&& value )
{
	_tokens.emplace(before, type, std::move(Literal(std::move(value))));
	auto output = before;
	return --output;
}

TokenIt TokenStream::emplace( const TokenIt& before, TokenType type, bool b )
{
	_tokens.emplace(before, type, std::move(Literal(b)));
	auto output = before;
	return --output;
}

TokenIt TokenStream::emplace( const TokenIt& before, TokenType type, int i, const std::optional<std::string>& integral_formated_value/* = std::nullopt*/ )
{
	_tokens.emplace(before, type, std::move(Literal(i, integral_formated_value)));
	auto output = before;
	return --output;
}

TokenIt TokenStream::emplace( const TokenIt& before, TokenType type, int64_t i, const std::optional<std::string>& integral_formated_value/* = std::nullopt*/ )
{
	_tokens.emplace(before, type, std::move(Literal(i, integral_formated_value)));
	auto output = before;
	return --output;
}

TokenIt TokenStream::emplace( const TokenIt& before, TokenType type, uint64_t i, const std::optional<std::string>& integral_formated_value/* = std::nullopt*/ )
{
	_tokens.emplace(before, type, std::move(Literal(i, integral_formated_value)));
	auto output = before;
	return --output;
}

TokenIt TokenStream::emplace( const TokenIt& before, TokenType type, double i, const std::optional<std::string>& integral_formated_value/* = std::nullopt*/ )
{
	_tokens.emplace(before, type, std::move(Literal(i, integral_formated_value)));
	auto output = before;
	return --output;
}

TokenIt TokenStream::emplace( const TokenIt& before, TokenType type, const std::shared_ptr<Symbol>& s, const std::string& symbol_name )
{
	_tokens.emplace(before, type, std::move(Literal(s, symbol_name)));
	auto output = before;
	return --output;
}

TokenIt TokenStream::emplace( const TokenIt& before, TokenType type, std::shared_ptr<Symbol>&& s, const std::string& symbol_name )
{
	_tokens.emplace(before, type, std::move(Literal(std::move(s), symbol_name)));
	auto output = before;
	return --output;
}

TokenIt TokenStream::emplace( const TokenIt& before, TokenType type, const Literal& literal )
{
	_tokens.emplace(before, type, literal);
	auto output = before;
	return --output;
}

TokenIt TokenStream::emplace( const TokenIt& before, TokenType type, Literal&& literal )
{
	_tokens.emplace(before, type, std::move(literal));
	auto output = before;
	return --output;
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

TokenIt TokenStream::erase( TokenIt element )
{
	return _tokens.erase(element);
}

TokenIt TokenStream::erase( TokenIt first, TokenIt last )
{
	return _tokens.erase(first, last);
}

void TokenStream::move_append( TokenStream* donor )
{
	_tokens.splice(_tokens.end(), donor->_tokens);
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

size_t TokenStream::size() const
{
	return _tokens.size();
}

bool TokenStream::empty() const
{
	return _tokens.empty();
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

TokenIt TokenStream::findBackwards( TokenType type )
{
	return findBackwards(type, begin(), end());
}

TokenIt TokenStream::findBackwards( TokenType type, TokenIt to )
{
	return findBackwards(type, begin(), to);
}

TokenIt TokenStream::findBackwards( TokenType type, TokenIt from, TokenIt to )
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
   // enum Type{
   //    Left,
   //    Right,
   // };

   // BracketEntry() = default;
   // BracketEntry(const BracketEntry&) = default;
   LeftBracketEntry(int line, int depth, int tabulator, bool put_new_lines) : _put_new_lines(put_new_lines), _tabulator(tabulator), _depth(depth), _line(line) {}
   // BracketEntry operator=(const BracketEntry&) = default;

   // bool isLeft() const { return _type == Left; }
   // bool isRight() const { return _type == Right; }
   int getLine() const { return _line; }
   int getTabulator() const { return _tabulator; }
   int getDepth() const { return _depth; }
   bool putNewLines() const { return _put_new_lines; }
private:
   bool _put_new_lines;
   int _tabulator;
   int _depth;
   int _line;
};

class BracketStack {
public:
   void addLeftBracket(int line, bool put_new_lines)
   {
      std::cout << "(" << std::endl;
      if( brackets.empty() )
         brackets.emplace_back(line, 1, 1, put_new_lines);
      else
      {
         const auto& previous = brackets.back();
         int tabulator = previous.getTabulator();
         if(line != previous.getLine())
            ++tabulator;
         int depth = previous.getDepth() + 1;
         brackets.emplace_back(line, depth, tabulator, put_new_lines);
      }
   }

   void addRightBracket(int line)
   {
      std::cout << ")" << std::endl;
      assert(!brackets.empty());
      brackets.pop_back();
   }

   /// @name Observe methods
   /// @{
   bool putNewlineInCurrentSector() const
   {
      if(brackets.empty())
         return false;
      return brackets.back().putNewLines();
   }

   int getTabulatorCount() const
   {
      if(brackets.empty())
         return 0;
      return brackets.back().getTabulator();
   }

   std::string getTabulators() const { return std::string(getTabulatorCount(), '\t'); }
   /// @}
private:
   std::vector<LeftBracketEntry> brackets;
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
         leftBrackets.pop();
      else if(current == NEW_LINE && !leftBrackets.empty())
         leftBrackets.top()->setFlag(true);
   }
}

std::string TokenStream::getText(bool withIncludes)
{
   determineNewlineSectors(); //TODO: Find a better place to call the function

   BracketStack brackets;
   uint lineCounter = 0;
   std::stringstream os;
   bool inside_rule = false;
   bool inside_hex_string = false;
   bool inside_hex_jump = false;
   bool inside_regexp = false;
   bool inside_enumeration_brackets = false;
   bool second_nibble = true;
   // auto nextIt = begin();
   // ++nextIt;
   for(auto it = begin(); it != end(); ++it/*, ++nextIt*/)
   {
      auto current = it->getType();
      if(current == INCLUDE_DIRECTIVE && withIncludes)
         continue;
      else if(current == INCLUDE_PATH)
      {
         assert(it->isIncludeToken());
         if(withIncludes){
            os << it->getIncludeSubstream()->getText(withIncludes);
            continue;
         }
         else
            os << *it;
      }
      else if(current == COMMENT && it != begin() && std::prev(it)->getType() == NEW_LINE)
      {
         os << it->getLiteral().getFormattedValue();
         os << *it;
      }
      else
         os << *it;

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

      if(current == LP || current == LP_ENUMERATION || current == HEX_JUMP_LEFT_BRACKET || current == REGEXP_START_SLASH || current == HEX_START_BRACKET || current == LP_WITH_SPACE_AFTER || current == LP_WITH_SPACES) {
         brackets.addLeftBracket(lineCounter, it->getFlag());
         if(brackets.putNewlineInCurrentSector() && next != NEW_LINE && next != COMMENT)
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
            brackets.addRightBracket(lineCounter);
      }
      if(current == NEW_LINE)
      {
         ++lineCounter;
         if(inside_rule && next != COMMENT && next != NEW_LINE)
         {
            if(next == META
               || next == STRINGS
               || next == CONDITION)
               os << "\t";
            else if(next != RULE_END)
               os << "\t\t" << brackets.getTabulators();
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
            case HEX_JUMP_VARYING:
            case HEX_JUMP_VARYING_RANGE:
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
               os << " ";
         }
      }
      else if(!inside_regexp && !inside_enumeration_brackets)
      {
         switch(current)
         {
            case NULLSYMBOL:
            case META:
            case STRINGS:
            case CONDITION:
            case UNARY_MINUS:
            case BITWISE_NOT:
            case INTEGER_FUNCTION:
            case FUNCTION_SYMBOL:
            case ARRAY_SYMBOL:
            case LP:
            case LSQB:
            case DOT:
               break;
            default:
               switch(next)
               {
                  case RP:
                  case RSQB:
                  case DOT:
                  case NEW_LINE:
                  case COMMA:
                     break;
                  case REGEXP_MODIFIERS:
                     if(current != REGEXP_MODIFIERS)
                        break;
                     [[fallthrough]];
                  default:
                     if(next != LSQB || ( current != STRING_OFFSET && current != STRING_LENGTH))
                        os << " ";
               }
         }
      }
      else if(inside_enumeration_brackets)
      {
         if(current != LP_ENUMERATION && next != RP_ENUMERATION && next != COMMA)
            os << " ";
      }
      else if(current == HEX_ALT_RIGHT_BRACKET || current == HEX_ALT_LEFT_BRACKET)
         os << " ";
   }
   return os.str();
}

/**
 * Counts all brackets in between t and next new line
 * @param t iterator from this TokenStream.
 */
// int TokenStream::minimalNumberOfTabs(TokenIt from)
// {
//    int counter = 0;
//    int minimal = 0;
//    for(TokenIt it = from; it != end(); ++it)
//    {
//       auto type = it->getType();
//       switch(type)
//       {
//          case NEW_LINE:
//             return minimal;
//          case LP:
//          case LP_ENUMERATION:
//          case HEX_JUMP_LEFT_BRACKET:
//          case REGEXP_START_SLASH:
//          case HEX_START_BRACKET:
//          case LP_WITH_SPACES:
//          case LP_WITH_SPACE_AFTER:
//             ++counter;
//             break;
//          case RP:
//          case RP_ENUMERATION:
//          case HEX_JUMP_RIGHT_BRACKET:
//          case REGEXP_END_SLASH:
//          case HEX_END_BRACKET:
//          case RP_WITH_SPACES:
//          case RP_WITH_SPACE_BEFORE:
//             --counter;
//             if(minimal > counter)
//                minimal = counter;
//             break;
//          default:
//             break;
//       }
//    }
//    return minimal;
// }

} //namespace yaramod
