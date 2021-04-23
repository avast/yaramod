/**
 * @file src/types/modules/module.cpp
 * @brief Implementation of class Module.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <sstream>

#include "yaramod/types/expression.h"
#include "yaramod/types/modules/module.h"
#include "yaramod/types/symbol.h"

namespace yaramod {

using Json = nlohmann::json;

/**
 * A mapping converting a given string to corresponding ExpressionType.
 */
std::optional<ExpressionType> stringToExpressionType (const std::string& str)
{
	if (str == "undefined")
		return ExpressionType::Undefined;
	else if (str == "bool" || str == "b")
		return ExpressionType::Bool;
	else if (str == "int" || str == "i")
		return ExpressionType::Int;
	else if (str == "string" || str == "s")
		return ExpressionType::String;
	else if (str == "regexp" || str == "r")
		return ExpressionType::Regexp;
	else if (str == "object" || str == "o")
		return ExpressionType::Object;
	else if (str == "float" || str == "f")
		return ExpressionType::Float;
	return std::nullopt;
}

/**
 * Constructor.
 *
 * @param name Name of the module
 * @param filePath path to the module contents
 */
Module::Module(const std::string& name, const std::string& filePath)
	: _name(name)
{
	addPath(filePath);
}

/**
 * Constructor.
 *
 * @param name Name of the module
 * @param fileContent module content
 */
Module::Module(const std::string& name, nlohmann::json&& json)
	: _name(name)
{
	addJson(json);
}

/**
 * Destructor.
 */
Module::~Module()
{
}

/**
 * Add source json to this module.
 */
void Module::addJson(const nlohmann::json& json)
{
	_jsons.push_back(json);
}

/**
 * Add path to this module. The json located on path will be read and added to module.
 */
void Module::addPath(const std::string& path)
{
	_filePaths.emplace_back(path, false);
}

/**
 * Returns the name of the module.
 *
 * @return Module name.
 */
const std::string& Module::getName() const
{
	return _name;
}

/**
 * Returns the paths to JSON files specifying the module.
 *
 * @return Module JSON file paths.
 */
std::vector<std::string> Module::getPaths() const
{
	std::vector<std::string> p;
	for (const auto& item : _filePaths)
		p.push_back(item.first);
	return p;
}

/**
 * Returns the paths to JSON files specifying the module as a single string.
 *
 * @return Module JSON file paths as a string.
 */
std::string Module::getPathsAsString() const
{
	std::stringstream ss;
	for (const auto& item : _filePaths)
		ss << "'" << item.first << "', ";
	auto message = ss.str();
	message.erase(message.size()-2, 2);
	return message;
}

/**
 * Returns the structure symbol of the module.
 *
 * @return Module structure symbol.
 */
const std::shared_ptr<StructureSymbol>& Module::getStructure() const
{
	return _structure;
}

/**
 * Returns whether the module is already initialized.
 *
 * @return @c true if initialized, otherwise @c false.
 */
bool Module::isInitialized() const
{
	return _structure != nullptr;
}

/**
 * Creates a dictionary or an array from given json depending on its `kind` value.
 *  - A structured iterable is created when the json contains `structure` entry.
 *  - Otherwise iterable without structure is created using `type` entry. 
 * @param json structure supplied in json to be created ("kind" must be "array" or "dictionary")
 * @param base already existing Structure which gets the new dictionary as its attribute. Must not be nullptr.
 */
void Module::_addIterable(StructureSymbol* base, const Json& json)
{
	assert(base);

	bool isDictionary = false;
	if (accessJsonString(json, "kind") == "dictionary")
		isDictionary = true;
	if (!isDictionary)
		assert(accessJsonString(json, "kind") == "array");

	auto name = accessJsonString(json, "name");
	std::string documentation = json.contains("documentation") ? accessJsonString(json, "documentation") : "";

	std::optional<std::shared_ptr<Symbol>> existing = base->getAttribute(name);
	if (existing)
	{
		if (isDictionary && existing.value()->getType() != Symbol::Type::Dictionary)
			throw ModuleError("Colliding definitions of " + name + " attribute with different kind. Expected dictionary." + getPathsAsString());
		if (!isDictionary && existing.value()->getType() != Symbol::Type::Array)
			throw ModuleError("Colliding definitions of " + name + " attribute with different kind. Expected array." + getPathsAsString());
		auto existingIterable = std::static_pointer_cast<IterableSymbol>(existing.value());
		if (json.contains("structure"))
		{
			auto structureJson = accessJsonSubjson(json, "structure");
			if (accessJsonString(structureJson, "kind") != "struct")
				throw ModuleError("Colliding definitions of " + name + " attribute. Expected embedded structure to have kind 'struct'." + getPathsAsString());
			if (accessJsonString(structureJson, "name") != name)
				throw ModuleError("Colliding definitions of " + name + " attribute. '" + name + "' != '" + accessJsonString(structureJson, "name") + "'." + getPathsAsString());
			if (structureJson.contains("attributes"))
			{
				if (!existingIterable->isStructured())
					throw ModuleError("Colliding definitions of " + name + " attribute. Unxpected structured iterable." + getPathsAsString());
				if (existingIterable->getElementType() != ExpressionType::Object)
					throw ModuleError("Not object");
				auto attributes = accessJsonArray(structureJson, "attributes");
				auto existingEmbeddedStructure = std::static_pointer_cast<StructureSymbol>(existingIterable->getStructuredElementType());
				for (const auto& attr : attributes)
					_addAttributeFromJson(existingEmbeddedStructure.get(), attr);
			}		
		}
		else if (existingIterable->isStructured())
			throw ModuleError("Colliding definitions of " + name + " attribute. Expected structured iterable." + getPathsAsString());
	}
	else
	{
		if (json.contains("structure"))
		{
			auto structureJson = accessJsonSubjson(json, "structure");
			auto embeddedStructure = _addStruct(nullptr, structureJson);

			if (isDictionary)
				base->addAttribute(std::make_shared<DictionarySymbol>(name, embeddedStructure, documentation));
			else
				base->addAttribute(std::make_shared<ArraySymbol>(name, embeddedStructure, documentation));
		}
		else
		{
			auto t = stringToExpressionType(accessJsonString(json, "type"));
			if (!t)
				throw ModuleError("Unknown dictionary type '" + accessJsonString(json, "type") + "'");
			auto type = t.value();
			if (isDictionary)
				base->addAttribute(std::make_shared<DictionarySymbol>(name, type, documentation));
			else
				base->addAttribute(std::make_shared<ArraySymbol>(name, type, documentation));
		}
	}
}

/**
 * Creates a function from supplied json and:
 *  - adds the new function as a attribute of structure base or
 *  - it modifies already existing attribute of base with the same name.
 *
 * @param json structure supplied in json to be created ("kind": "function")
 * @param base already existing Structure which gets the new function as its attribute
 */
void Module::_addFunctions(StructureSymbol* base, const Json& json)
{
	assert(accessJsonString(json, "kind") == "function");
	assert(base);

	auto name = accessJsonString(json, "name");
	auto returnType = stringToExpressionType(accessJsonString(json, "return_type"));
	if (!returnType)
		throw ModuleError("Unknown function return type type '" + accessJsonString(json, "return_type") + "'");

	auto overloads = accessJsonArray(json, "overloads");
	for (const auto& overload : overloads)
	{
		auto typeVector = std::vector<ExpressionType> {returnType.value()};
		std::vector<std::string> argumentNames;
		auto arguments = accessJsonArray(overload, "arguments");

		for (const auto& item : arguments)
		{
			auto arg_name = item.contains("name") ? accessJsonString(item, "name") : "";
			argumentNames.push_back(arg_name);

			auto t = accessJsonString(item, "type");
			auto arg_type = stringToExpressionType(t);
			if (!arg_type)
				throw ModuleError("Unknown function parameter type '" + t + "'");
			typeVector.emplace_back(arg_type.value());
		}

		std::string documentation = overload.contains("documentation") ? accessJsonString(overload, "documentation") : "";
		std::vector<std::string> names{};

		auto function = std::make_shared<FunctionSymbol>(name, documentation, argumentNames, typeVector);
		base->addAttribute(function);
	}
}

/**
 * Creates a structure from supplied json
 * If base is supplied, this method returns nullptr and it either:
 *  - adds structure from json as a attribute of base or
 *  - it modifies already existing attribute of base with the same name.
 * If base is nullptr, this method returns new Structure constructed from supplied json
 *
 * @param json structure supplied in json to be created ("kind": "struct")
 * @param base already existing Structure which gets the new structure as its attribute. Can be nullptr.
 */
std::shared_ptr<StructureSymbol> Module::_addStruct(StructureSymbol* base, const Json& json)
{
	assert(accessJsonString(json, "kind") == "struct");

	auto name = accessJsonString(json, "name");
	auto attributes = accessJsonArray(json, "attributes");

	// Before creating new structure we first look for its existence within base attributes:	
	std::optional<std::shared_ptr<Symbol>> existing = base ? base->getAttribute(name) : std::nullopt;
	if (existing)
	{
		if (existing.value()->getType() != Symbol::Type::Structure)
			throw ModuleError("Expected " + name + " to be a struct within the module json files:\n" + getPathsAsString());
		auto existingStructure = std::static_pointer_cast<StructureSymbol>(existing.value());
		for (const auto& attr : attributes)
			_addAttributeFromJson(existingStructure.get(), attr);
	}
	else
	{
		auto newStructure = std::make_shared<StructureSymbol>(name);
		for (const auto& attr : attributes)
			_addAttributeFromJson(newStructure.get(), attr);
		if (!base)
			return newStructure;
		base->addAttribute(newStructure);
	}
	return nullptr;
}

/**
 * Creates a value from supplied json and:
 * adds the new value as a attribute of structure base.
 * When already existing attribute of base with specified name,
 * this method checks that the values are the same.
 *
 * @param json structure supplied in json to be created ("kind": "value")
 * @param base already existing Structure which gets the new value as its attribute. Must not be nullptr
 */
void Module::_addValue(StructureSymbol* base, const Json& json)
{
	assert(accessJsonString(json, "kind") == "value");
	assert(base);

	auto name = accessJsonString(json, "name");
	auto t = stringToExpressionType(accessJsonString(json, "type"));
	std::string documentation = json.contains("documentation") ? accessJsonString(json, "documentation") : "";

	if (!t)
		throw ModuleError("Unknown value type '" + accessJsonString(json, "type") + "'");
	auto type = t.value();

	// Before creating new structure we first look for its existence within base attributes:	
	std::optional<std::shared_ptr<Symbol>> existing = base->getAttribute(name);
	if (existing)
	{
		if (existing.value()->getType() != Symbol::Type::Value)
			throw ModuleError("Colliding definitions of " + name + " attribute with different kind. Expected value." + getPathsAsString());
		if (existing.value()->getDataType() != type)
			throw ModuleError("Colliding definitions of " + name + " attribute. The value is defined twice with different types. " + getPathsAsString());
	}
	else
	{
		auto newValue = std::make_shared<ValueSymbol>(name, type, documentation);
		base->addAttribute(newValue);
	}
}

/**
 * Handler method to controll unwrapping of the json based on its `kind` entry.
 *
 * @param json structure to be parsed
 * @param structure to be modified by adding attribute built according to the json content
 */
void Module::_addAttributeFromJson(StructureSymbol* base, const Json& json)
{
	auto kind = accessJsonString(json, "kind");
	if (kind == "function")
		_addFunctions(base, json);
	else if (kind == "struct")
		_addStruct(base, json);
	else if (kind == "value")
		_addValue(base, json);
	else if (kind == "dictionary" || kind == "array")
		_addIterable(base, json);
	else
		throw ModuleError("Unknown kind entry '" + kind + "'");
}

/**
 * Initializes module structure.
 *
 * @return @c true if success, otherwise @c false.
 */
bool Module::initialize()
{
	if (_filePaths.empty() && _jsons.empty())
		throw ModuleError("No .json file supplied to initialize a module.");

	for (auto& filePath : _filePaths)
	{
		if (!filePath.second)
		{
			addJson(readJsonFile(filePath.first));
			filePath.second = true;
		}
	}

	for (const auto& json : _jsons)
		_importJson(json);

	return true;
}

void Module::_importJson(const Json& json)
{
	auto name = accessJsonString(json, "name");

	if (name == std::string{})
		throw ModuleError("Module name must be non-empty.");
	else if (!_structure) // First iteration - need to create the structure.
		_structure = _addStruct(nullptr, json);
	else if (_name != name) // Throws - name of the module must be the same accross the files.
		throw ModuleError("Module name must be the same in all files, but " + name + " != " + _name + ".\n" + getPathsAsString());
	else // _struct already created, need only to add new attributes
	{
		const auto& attributes = accessJsonArray(json, "attributes");
		for (const auto& attr : attributes)
			_addAttributeFromJson(_structure.get(), attr);
	}
}

}
