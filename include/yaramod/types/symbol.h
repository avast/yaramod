/**
 * @file src/types/symbol.h
 * @brief Declaration of class Symbol.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

#include <algorithm>
#include <cassert>
#include <string>
#include <unordered_map>

#include "yaramod/types/expression.h"
//#include "yaramod/types/literal.h"

namespace yaramod {

/**
 * Abstract class for representing symbols of the identifiers.
 * Symbols can be of type value symbol (representing dummy symbol or integer/string value),
 * array symbol (representing array object), dictionary symbol (representing dictionary object),
 * function symbol (representing function) or structure symbol (representing structure object).
 * Symbols carry certain data type of the expression. Data type depends on what symbol represents.
 */
class Symbol
{
public:
	/// Type of the symbol.
	enum class Type
	{
		Value      = 1 << 0,
		Array      = 1 << 1,
		Dictionary = 1 << 2,
		Function   = 1 << 3,
		Structure  = 1 << 4
	}; // if(type & (Value|Structure))

	/// @name Destructor
	/// @{
	virtual ~Symbol() = default;
	/// @}

	/// @name Getter methods
	/// @{
	const std::string& getName() const { return _name; }
	Expression::Type getDataType() const { return _dataType; }
	TokenType getTokenType() const
	{
		switch(_type)
		{
			case Type::Value : return VALUE_SYMBOL;
			case Type::Array : return ARRAY_SYMBOL;
			case Type::Dictionary : return DICTIONARY_SYMBOL;
			case Type::Function : return FUNCTION_SYMBOL;
			case Type::Structure : return STRUCTURE_SYMBOL;
		}
	}
	/// @}

	/// @name Detection methods
	/// @{
	bool isValue() const { return _type == Symbol::Type::Value; }
	bool isArray() const { return _type == Symbol::Type::Array; }
	bool isDictionary() const { return _type == Symbol::Type::Dictionary; }
	bool isFunction() const { return _type == Symbol::Type::Function; }
	bool isStructure() const { return _type == Symbol::Type::Structure; }
	/// @}
	// friend std::ostream& operator<<(std::ostream& os, const Symbol& symbol) {
 //   	os << symbol._name;
 //      return os;
 //   }
protected:
	/// @name Constructors
	/// @{
	Symbol(Symbol::Type type, const std::string& name, Expression::Type dataType)
		: _type(type), _name(name), _dataType(dataType) {}
	// Symbol(Symbol::Type type, TokenIt name, Expression::Type dataType)
	// 	: _type(type), _name(name), _dataType(dataType) {}
	/// @}

	Symbol::Type _type; ///< Type of the symbol
	std::string _name; ///< Name
	Expression::Type _dataType; ///< Data type of the symbol
};

}
