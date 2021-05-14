/**
 * @file src/types/modules/module_pool.h
 * @brief Declaration of class ModulePool.
 * @copyright (c) 2021 Avast Software, licensed under the MIT license
 */

#pragma once

#include "yaramod/utils/filesystem.h"
#include "yaramod/types/features.h"
#include "yaramod/types/modules/generated/module_list.h"
#include "yaramod/types/modules/module.h"

#include <map>

namespace yaramod {

/**
 * Class maintaining importable modules.
 */
class ModulePool {
public:
	/**
	 * Constructor.
	 *
	 * When environmental variable YARAMOD_MODULE_SPEC_PATH is set, we create all modules from it and only from it.
	 *
	 * Otherwise we load all modules specified in generated ModuleList and also when directory is nonempty, we load all modules from there too.
	 *
	 * @param directory The directory to load the modules from apart from YARAMOD_MODULE_SPEC_PATH
	 */
	ModulePool(Features features, const std::string& directory);
	/**
	 * Loads the module based on its name from the table of known modules.
	 *
	 * @param name Name of the module to load
	 * @param features Determines which symbols to import
	 *
	 * @return Module if found, @c nullptr otherwise.
	 */
	std::shared_ptr<Module> load(const std::string& name);
	/**
	 *
	 * Method returns sorted map of pointers to modules stored.
	 *
	 * @return modules stored.
	 */
	std::map<std::string, Module*> getModules() const;

private:
	void _init(const std::string& directory);
	bool _processPath(fs::path path);
	void _processModuleContent(const ModuleContent& content);
	Features _features;
	std::unordered_map<std::string, std::shared_ptr<Module>> _knownModules = {}; ///< Table of all known modules
	modules::ModuleList _moduleList; ///< list of contents of the modules to be loaded from JSON
};

} //namespace yaramod
