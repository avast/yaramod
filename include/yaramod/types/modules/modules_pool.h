/**
 * @file src/types/modules/modules_pool.h
 * @brief Declaration of class Module.
 * @copyright (c) 2020 Avast Software, licensed under the MIT license
 */

#pragma once

#include "yaramod/types/modules/generated/modules_list.h"
#include "yaramod/types/modules/module.h"

#include <filesystem>

namespace yaramod {

/**
 * Class maintaining importable modules.
 */
class ModulesPool {
public:
	/*
	 * When environmental variable YARAMOD_MODULE_SPEC_PATH is set, we load all modules from it.
	 * Additionaly to YARAMOD_MODULE_SPEC_PATH we load all modules
	 * specified by ModuleList
	 */
	ModulesPool();
	/**
	 * Loads the module based on its name from the table of known modules.
	 *
	 * @param name Name of the module to load
	 * @param features Determines which symbols to import
	 *
	 * @return Module if found, @c nullptr otherwise.
	 */
	std::shared_ptr<Module> load(const std::string& name)
	{
		auto itr = _knownModules.find(name);
		// Check that the module exists
		if (itr == _knownModules.end())
			return nullptr;

		// Initialize the module if it is not already initialized.
		if (!itr->second->isInitialized())
			itr->second->initialize();

		return itr->second;
	}

private:
	bool _init();
	bool _processPath(std::filesystem::path path);
	bool _processModuleContent(const ModuleContent& content);
	std::unordered_map<std::string, std::shared_ptr<Module>> _knownModules = {}; ///< Table of all known modules
	modules::ModulesList _modules_list; ///< list of contents of the modules to be loaded from JSON
};

} //namespace yaramod
