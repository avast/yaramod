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
 * Finds an attribute with specified name for a structure or iterable base.
 */
std::optional<std::shared_ptr<Symbol>> _getExistingAttribute(Symbol* base, std::string& name)
{
	if (base)
	{
		switch (base->getType())
		{
			case Symbol::Type::Structure:
				if (auto structure = dynamic_cast<StructureSymbol*>(base))
					return structure->getAttribute(name);
				break;
			case Symbol::Type::Array:
			case Symbol::Type::Dictionary:
				if (auto iterable = dynamic_cast<IterableSymbol*>(base))
				{
					auto structElement = iterable->getStructuredElementType();
					return structElement ? std::make_optional(structElement) : std::nullopt;
				}
				break;
			default:
				break;
		}
	}
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
			auto kind = accessJsonString(structureJson, "kind");

			if (accessJsonString(structureJson, "name") != name)
				throw ModuleError("Colliding definitions of " + name + " attribute. '" + name + "' != '" + accessJsonString(structureJson, "name") + "'." + getPathsAsString());

			if (kind == "reference")
			{
				auto type = accessJsonString(structureJson, "type");
				if (_stringToSymbol(nullptr, type) != existingIterable->getStructuredElementType())
					throw ModuleError("Colliding definitions of " + name + " attribute. Unxpected referenced type." + getPathsAsString());
			}
			else if (kind == "struct")
			{
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
			else
			{
				throw ModuleError("Colliding definitions of " + name + " attribute. Expected embedded structure to have kind 'struct' or 'reference'." + getPathsAsString());
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

			std::shared_ptr<Symbol> templateAttribute;
			if (isDictionary)
				templateAttribute = std::make_shared<DictionarySymbol>(name, ExpressionType::Object, documentation);
			else
				templateAttribute = std::make_shared<ArraySymbol>(name, ExpressionType::Object, documentation);

			base->addTemplateAttribute(templateAttribute);

			if (accessJsonString(structureJson, "kind") == "reference")
				_addReference(templateAttribute.get(), structureJson);
			else
				_addStruct(templateAttribute.get(), structureJson, nullptr);

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
 * If base is supplied, this method either:
 *  - adds structure from json as an attribute of base and saves it to ref if supllied or
 *  - it modifies already existing attribute of base with the same name.
 * If base is nullptr, this method constructs new Structure from supplied json and saves to ref if supllied
 *
 * @param ref pointer to where the Structure gets saved. Can be nullptr.
 * @param json structure supplied in json to be created ("kind": "struct")
 * @param base already existing Structure or Iterable which gets the new structure as its attribute. Can be nullptr.
 */
void Module::_addStruct(Symbol* base, const Json& json, std::shared_ptr<StructureSymbol>* ref)
{
	assert(accessJsonString(json, "kind") == "struct");

	auto name = accessJsonString(json, "name");
	auto attributes = accessJsonArray(json, "attributes");

	// Before creating new structure we first look for its existence within base attributes:
	std::optional<std::shared_ptr<Symbol>> existing = _getExistingAttribute(base, name);
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

		if (ref)
		{
			*ref = std::move(newStructure);
			_addObjectToBase(base, *ref);

			for (const auto& attr : attributes)
				_addAttributeFromJson(ref->get(), attr);
		}
		else
		{
			_addObjectToBase(base, newStructure);
			for (const auto& attr : attributes)
				_addAttributeFromJson(newStructure.get(), attr);
		}
	}
}

/**
 * Creates a reference from supplied json and:
 * adds the new reference as a attribute of structure or iterable base.
 * When already existing attribute of base with specified name,
 * this method checks that the references are the same.
 *
 * @param json reference supplied in json to be created ("kind": "reference")
 * @param base already existing Structure or Iterable which gets the new reference as its attribute. Can't be nullptr
 */
void Module::_addReference(Symbol* base, const Json& json)
{
	assert(accessJsonString(json, "kind") == "reference");

	auto name = accessJsonString(json, "name");
	auto symbol = _stringToSymbol(nullptr, accessJsonString(json, "type"));

	if (!symbol)
		throw ModuleError("Unknown symbol '" + accessJsonString(json, "type") + "'");

	// Before creating new reference we first look for its existence within base attributes:
	std::optional<std::shared_ptr<Symbol>> existing = _getExistingAttribute(base, name);
	if (existing)
	{
		if (existing.value()->getType() != Symbol::Type::Reference)
			throw ModuleError("Colliding definitions of " + name + " attribute with different kind. Expected reference." + getPathsAsString());
		auto existingReference = std::static_pointer_cast<ReferenceSymbol>(existing.value());
		if (existingReference->getSymbol() != symbol)
			throw ModuleError("Colliding definitions of " + name + " attribute. The value is defined twice with different references. " + getPathsAsString());
	}
	else
	{
		_addObjectToBase(base, std::make_shared<ReferenceSymbol>(name, symbol));
	}
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
		_addStruct(base, json, nullptr);
	else if (kind == "reference")
		_addReference(base, json);
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
		_addStruct(nullptr, json, &_structure);
	else if (_name != name) // Throws - name of the module must be the same accross the files.
		throw ModuleError("Module name must be the same in all files, but " + name + " != " + _name + ".\n" + getPathsAsString());
	else // _struct already created, need only to add new attributes
	{
		const auto& attributes = accessJsonArray(json, "attributes");
		for (const auto& attr : attributes)
			_addAttributeFromJson(_structure.get(), attr);
	}
}

/**
 * A mapping converting a given string to corresponding Symbol.
 */
std::shared_ptr<Symbol> Module::_stringToSymbol (const std::shared_ptr<Symbol>& base, const std::string& str)
{
	std::string current_attribute = str;
	std::string next_attribute;
	auto delim_index = str.find('.');

	if (delim_index != std::string::npos)
	{
		current_attribute = str.substr(0, delim_index);
		next_attribute = str.substr(delim_index + 1, str.length());
	}

	if (!base)
	{
		if (_structure->getName() != current_attribute)
			throw ModuleError("Unaccessible namespace. You can reference objects only from the same module." + getPathsAsString());

		if (!next_attribute.empty())
			return _stringToSymbol(_structure, next_attribute);
		else
			return _structure;
	}
	else
	{
		if (base->getType() != Symbol::Type::Structure)
			throw ModuleError("Can't access an attribute of " + base->getName() + " as it's not a structured object." + getPathsAsString());

		auto baseStruct = std::static_pointer_cast<StructureSymbol>(base);
		auto found_symbol = baseStruct->getAttribute(current_attribute);

		if (!found_symbol)
			throw ModuleError("Object " + base->getName() + " does not contain an attribute with the name of " + current_attribute + "." + getPathsAsString());

		auto current_symbol = found_symbol.value();

		if (current_symbol->getType() == Symbol::Type::Dictionary ||
			current_symbol->getType() == Symbol::Type::Array)
		{
			auto current_iterable = std::static_pointer_cast<IterableSymbol>(current_symbol);
			current_symbol = current_iterable->getStructuredElementType();
		}

		if (!next_attribute.empty())
		{
			auto newBase = std::static_pointer_cast<StructureSymbol>(current_symbol);
			return _stringToSymbol(newBase, next_attribute);
		}

		return current_symbol;
	}
}

/**
 * Adds an attribute to it's base that can be either a parent structure or an iterable.
 */
void Module::_addObjectToBase(Symbol* base, std::shared_ptr<Symbol> newAttribute)
{
	if (base)
	{
		switch (base->getType())
		{
			case Symbol::Type::Structure:
				if (auto structure = dynamic_cast<StructureSymbol*>(base))
					structure->addAttribute(newAttribute);
				else
					throw ModuleError("Base could not be casted to a structure." + getPathsAsString());
				break;
			case Symbol::Type::Array:
			case Symbol::Type::Dictionary:
				if (auto iterable = dynamic_cast<IterableSymbol*>(base))
					iterable->setStructuredElementType(newAttribute);
				else
					throw ModuleError("Base could not be casted to an iterable." + getPathsAsString());
				break;
			default:
				throw ModuleError("Base type has to be a structure or an iterable." + getPathsAsString());
		}
	}
}

}
