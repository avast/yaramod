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

#include "yaramod/types/expression_type.h"
#include "yaramod/types/token_type.h"

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
		Value,
		Array,
		Dictionary,
		Function,
		Structure,
		Reference,
		Undefined
	};

	/// @name Constructors
	/// @{
	Symbol(Symbol::Type type, const std::string& name, ExpressionType dataType, const std::string& documentation = "")
		: _type(type), _name(name), _documentation(documentation), _dataType(dataType)
	{
	}
	/// @}

	/// @name Destructor
	/// @{
	virtual ~Symbol() = default;
	/// @}

	/// @name Getter methods
	/// @{
	const std::string& getName() const { return _name; }
	const std::string& getDocumentation() const { return _documentation; }
	ExpressionType getDataType() const { return _dataType; }
	Symbol::Type getType() const { return _type; }
	TokenType getTokenType() const
	{
		switch(_type)
		{
			case Type::Value : return TokenType::VALUE_SYMBOL;
			case Type::Array : return TokenType::ARRAY_SYMBOL;
			case Type::Dictionary : return TokenType::DICTIONARY_SYMBOL;
			case Type::Function : return TokenType::FUNCTION_SYMBOL;
			case Type::Structure : return TokenType::STRUCTURE_SYMBOL;
			case Type::Reference : return TokenType::REFERENCE_SYMBOL;
			case Type::Undefined : return TokenType::UNDEFINED;
			default: return TokenType::INVALID;
		}
	}
	/// @}

	/// @name Setter methods
	/// @{
	template<typename T>
	void setName(T&& name) { _name = std::forward<T>(name); }
	/// @}

	/// @name Detection methods
	/// @{
	bool isValue() const { return _type == Symbol::Type::Value; }
	bool isArray() const { return _type == Symbol::Type::Array; }
	bool isDictionary() const { return _type == Symbol::Type::Dictionary; }
	bool isFunction() const { return _type == Symbol::Type::Function; }
	bool isStructure() const { return _type == Symbol::Type::Structure; }
	bool isReference() const { return _type == Symbol::Type::Reference; }
	bool isUndefined() const { return _type == Symbol::Type::Undefined; }
	/// @}

protected:

	Symbol::Type _type; ///< Type of the symbol
	std::string _name; ///< Name
	std::string _documentation; ///< Documentation
	ExpressionType _dataType; ///< Data type of the symbol
};

}
