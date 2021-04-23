/**
 * @file src/types/modules/module.h
 * @brief Declaration of class Module.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

#include <memory>
#include <string>

#include "yaramod/utils/json.h"
#include "yaramod/types/symbols.h"
#include "yaramod/yaramod_error.h"

namespace yaramod {

/**
 * Class representing error in module specification.
 */
class ModuleError : public YaramodError
{
public:
	ModuleError(const std::string& errorMsg)
		: YaramodError(errorMsg)
	{
	}
	ModuleError(const ModuleError&) = default;
};

/**
 * Abstract class representing importable module. Every module
 * has to provide its structure in virtual method @c initialize.
 */
class Module
{
public:
	/// @name Constructors
	/// @{
	Module(const std::string& name, const std::string& path);
	Module(const std::string& name, nlohmann::json&& json);
	/// @}

	/// @name Destructor
	/// @{
	virtual ~Module();
	/// @}

	/// @name Initialization method
	/// @{
	bool initialize();
	void addPath(const std::string& path);
	void addJson(const nlohmann::json& json);
	/// @}

	/// @name Getter methods
	/// @{
	const std::string& getName() const;
	std::string getPathsAsString() const;
	std::vector<std::string> getPaths() const;
	const std::shared_ptr<StructureSymbol>& getStructure() const;
	/// @}

	/// @name Detection methods
	/// @{
	bool isInitialized() const;
	/// @}

protected:
	void _addAttributeFromJson(StructureSymbol* base, const nlohmann::json& json);
	void _addIterable(StructureSymbol* base, const nlohmann::json& json);
	void _addFunctions(StructureSymbol* base, const nlohmann::json& json);
	std::shared_ptr<StructureSymbol> _addStruct(StructureSymbol* base, const nlohmann::json& json);
	void _addValue(StructureSymbol* base, const nlohmann::json& json);
	void _importJson(const nlohmann::json& json);

	std::string _name; ///< Name of the module
	std::vector<std::pair<std::string, bool>> _filePaths; ///< The custom paths to JSON files which help to determine this module. Elements: [<path>, true iff <path> was loaded]. May be empty if no private modules.
	std::vector<nlohmann::json> _jsons; ///< The jsons which determine this module
	std::shared_ptr<StructureSymbol> _structure; ///< Structure of the module
};

}
