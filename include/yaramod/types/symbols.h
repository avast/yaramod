/**
 * @file src/types/symbols.h
 * @brief Declaration of all Symbol subclasses.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

#include <optional>
#include <vector>

#include "yaramod/types/symbol.h"

namespace yaramod {

/**
 * Class representing value symbol. Value symbol carries only name
 * of the symbol and some data type.
 */
class ValueSymbol : public Symbol
{
public:
	ValueSymbol(const std::string& name, ExpressionType dataType, const std::string& documentation = "") : Symbol(Symbol::Type::Value, name, dataType, documentation) {}
};

/**
 * Abstract class representing iterable symbol. Iterable symbol may be
 * array or dictionary symbol. Iterable symbols store data type of the elements
 * they are iterating over. If the element type is @c ExpressionType::Object then
 * iterable symbol also carries the symbol representing structured type of the element.
 */
class IterableSymbol : public Symbol
{
public:
	ExpressionType getElementType() const { return _elementType; }
	const std::shared_ptr<Symbol>& getStructuredElementType() const { return _structuredType; }

	bool isStructured() const { return _elementType == ExpressionType::Object && _structuredType; }

protected:
	IterableSymbol(Symbol::Type type, const std::string& name, ExpressionType elementType, const std::string& documentation)
		: Symbol(type, name, ExpressionType::Object, documentation), _elementType(elementType), _structuredType() {}
	IterableSymbol(Symbol::Type type, const std::string& name, const std::shared_ptr<Symbol>& structuredType, const std::string& documentation)
		: Symbol(type, name, ExpressionType::Object, documentation), _elementType(ExpressionType::Object), _structuredType(structuredType) {}

	ExpressionType _elementType; ///< Element of the iterated data
	std::shared_ptr<Symbol> _structuredType; ///< Structured type of the object elements
};

/**
 * Class representing array symbol. Array symbol carries name of the array and type of the element of the array.
 * Data type of the whole array symbol is always @c Symbol::Type::Array.
 */
class ArraySymbol : public IterableSymbol
{
public:
	ArraySymbol(const std::string& name, ExpressionType elementType, const std::string& documentation = "") : IterableSymbol(Symbol::Type::Array, name, elementType, documentation) {}
	ArraySymbol(const std::string& name, const std::shared_ptr<Symbol>& structuredType, const std::string& documentation = "") : IterableSymbol(Symbol::Type::Array, name, structuredType, documentation) {}
};

/**
 * Class representing dictionary symbol. Dictionary symbol carries name of the dictionary and type of the element of the dictionary.
 * Data type of the whole dictionary symbol is always @c Symbol::Type::Dictionary.
 */
class DictionarySymbol : public IterableSymbol
{
public:
	DictionarySymbol(const std::string& name, ExpressionType elementType, const std::string& documentation = "") : IterableSymbol(Symbol::Type::Dictionary, name, elementType, documentation) {}
	DictionarySymbol(const std::string& name, const std::shared_ptr<Symbol>& structuredType, const std::string& documentation = "") : IterableSymbol(Symbol::Type::Dictionary, name, structuredType, documentation) {}
};

/**
 * Class representing function symbol. Function symbol carries name of the function, return type of the function
 * and argument types of all possible overloads of that function.
 */
class FunctionSymbol : public Symbol
{
public:
	template <typename... Args>
	FunctionSymbol(const std::string& name, ExpressionType returnType, const Args&... args)
		: FunctionSymbol(name, "", {""}, returnType, args...)
	{
	}

	template <typename... Args>
	FunctionSymbol(const std::string& name, const std::string& documentation, const std::vector<std::string>& argumentsNames, ExpressionType returnType, const Args&... args)
		: Symbol(Symbol::Type::Function, name, ExpressionType::Object), _returnType(returnType), _argTypesOverloads(1)
	{
		_initArgs(args...);
		_addDocumentation(documentation, argumentsNames);
	}

	// The first element of @param type is the return type, then the arguments types follow.
	FunctionSymbol(const std::string& name, const std::vector<ExpressionType>& type)
		: FunctionSymbol(name, "", {""}, type)
	{
	}

	// The first element of @param type is the return type, then the arguments types follow.
	FunctionSymbol(const std::string& name, const std::string& documentation, const std::vector<std::string>& argumentsNames, const std::vector<ExpressionType>& type)
		: Symbol(Symbol::Type::Function, name, ExpressionType::Object), _argTypesOverloads(1)
	{
		assert(type.size() > 0 && "Return type must be specified.");
		_returnType = type[0];
		for (auto arg = ++type.begin(); arg != type.end(); ++arg)
			_initAddArgument(*arg);
		_addDocumentation(documentation, argumentsNames);
	}

	ExpressionType getReturnType() const { return _returnType; }
	const std::vector<std::vector<ExpressionType>>& getAllOverloads() const { return _argTypesOverloads; }

	std::size_t getArgumentCount(std::size_t overloadIndex = 0) const
	{
		assert(overloadIndex < _argTypesOverloads.size());
		return _argTypesOverloads[overloadIndex].size();
	}

	const std::vector<ExpressionType>& getArgumentTypes(std::size_t overloadIndex = 0) const
	{
		assert(overloadIndex < _argTypesOverloads.size());
		return _argTypesOverloads[overloadIndex];
	}

	const std::vector<std::vector<std::string>> getAllArgumentNames() const
	{
		return _overloadArgumentsNames;
	}

	const std::vector<std::string> getArgumentNames(std::size_t overloadIndex = 0) const
	{
		assert(overloadIndex < _overloadArgumentsNames.size());
		return _overloadArgumentsNames[overloadIndex];
	}

	const std::vector<std::string>& getAllDocumentations() const { return _overloadDocumentations; }

	const std::string& getDocumentation(std::size_t overloadIndex = 0) const
	{
		assert(overloadIndex < _overloadDocumentations.size());
		assert(_overloadDocumentations.size() == _argTypesOverloads.size());
		return _overloadDocumentations[overloadIndex];
	}

	bool addOverload(const std::vector<ExpressionType>& argTypes, const std::string& documentation = "", const std::vector<std::string>& argumentsNames = {})
	{
		if (overloadExists(argTypes))
			return false;

		_argTypesOverloads.push_back(argTypes);
		_addDocumentation(documentation, argumentsNames);
		return true;
	}
	
	bool overloadExists(const std::vector<ExpressionType>& args) const
	{
		for (const auto& overload : _argTypesOverloads)
		{
			if (overload.size() != args.size())
				continue;

			// No mismatch in two vectors, so they are completely the same.
			auto mismatch = std::mismatch(overload.begin(), overload.end(), args.begin());
			if (mismatch.first == overload.end())
				return true;
		}

		return false;
	}

private:
	void _addDocumentation(const std::string& documentation, const std::vector<std::string>& argumentsNames)
	{
		_overloadDocumentations.push_back(documentation);
		_overloadArgumentsNames.push_back(argumentsNames);
	}

	void _initArgs() {}

	template <typename... Args>
	void _initArgs(ExpressionType argType, const Args&... args)
	{
		_initAddArgument(argType);
		_initArgs(args...);
	}

	void _initAddArgument(ExpressionType argType)
	{
		_argTypesOverloads.front().push_back(argType);
	}

	ExpressionType _returnType; ///< Return type of the function
	std::vector<std::vector<ExpressionType>> _argTypesOverloads; ///< All possible overloads of the function
	std::vector<std::string> _overloadDocumentations; ///< Documentation of all known overloads
	std::vector<std::vector<std::string>> _overloadArgumentsNames; ///< Names of arguments of all known overloads
};

/**
 * Class representing structure symbol. Structure symbol carries name of the structure and its attributes.
 */
class StructureSymbol : public Symbol
{
public:
	StructureSymbol(const std::string& name) : Symbol(Symbol::Type::Structure, name, ExpressionType::Object) {}

	std::optional<std::shared_ptr<Symbol>> getAttribute(const std::string& name) const
	{
		auto itr = _attributes.find(name);
		if (itr == _attributes.end())
			return std::nullopt;

		return { itr->second };
	}

	const std::unordered_map<std::string, std::shared_ptr<Symbol>>& getAttributes() const
	{
		return _attributes;
	}

	bool addAttribute(const std::shared_ptr<Symbol>& attribute)
	{
		// Insertion result is pair of iterator and boolean indicator whether insertion was successful
		auto insertionResult = _attributes.emplace(attribute->getName(), attribute);
		if (insertionResult.second)
			return true;

		// Insertion did not succeed and we must handle that
		auto itr = insertionResult.first;

		// If we are trying to add a function and function with that name already exists,
		// it may be function overload, so check that.
		if (itr->second->isFunction() && attribute->isFunction())
		{
			auto oldFunction = std::static_pointer_cast<FunctionSymbol>(itr->second);
			auto newFunction = std::static_pointer_cast<const FunctionSymbol>(attribute);

			// Overload return types must be the same, only argument count and types may differ.
			if (oldFunction->getReturnType() != newFunction->getReturnType())
				return false;

			return oldFunction->addOverload(newFunction->getArgumentTypes(), newFunction->getDocumentation(), newFunction->getArgumentNames());
		}

		return false;
	}

private:
	std::unordered_map<std::string, std::shared_ptr<Symbol>> _attributes; ///< Attributes of the structure
};


class ReferenceSymbol : public Symbol
{
public:
	ReferenceSymbol(const std::string& name, const std::shared_ptr<Symbol>& symbol) : Symbol(Symbol::Type::Reference, name, ExpressionType::Object), _symbol(symbol) {}

	const std::shared_ptr<Symbol>& getSymbol() const
	{
		return _symbol;
	}

private:
	std::shared_ptr<Symbol> _symbol;
};

}
