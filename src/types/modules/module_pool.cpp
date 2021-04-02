/**
 * @file src/types/modules/module_pool.cpp
 * @brief Implementation of CustomModule.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <sstream>

#include "yaramod/types/modules/module_pool.h"


namespace yaramod {

using Json = nlohmann::json;

ModulePool::ModulePool(const std::string& directory)
{
	_init(directory);

	// Initializes all modules
	for (auto itr = _knownModules.begin(); itr != _knownModules.end(); ++itr)
		itr->second->initialize();
}

std::shared_ptr<Module> ModulePool::load(const std::string& name)
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

std::map<std::string, Module*> ModulePool::getModules() const
{
	std::map<std::string, Module*> m;
	for (const auto& item : _knownModules)
	{
		m.insert(std::pair(item.first, item.second.get()));
	}
	return m;
}

bool ModulePool::_processPath(std::filesystem::path p)
{
	if (p.extension() != ".cpp" && p.extension() != ".json")
		return false;

	auto path = p.string();

	auto json = readJsonFile(path);
	if (!json.contains("kind") || accessJsonString(json, "kind") != "struct")
		return false;

	auto name = accessJsonString(json, "name");
	auto itr = _knownModules.find(name);
	if (itr == _knownModules.end())
	{
		auto module = std::make_shared<Module>(name, path);
		_knownModules.emplace(std::make_pair(name, std::move(module)));
	}
	else
		itr->second->addPath(path);

	return true;
}

void ModulePool::_processModuleContent(const ModuleContent& content)
{
	auto json = readJsonString(content.getContent());
	assert(json.contains("kind") && accessJsonString(json, "kind") == "struct");

	auto name = accessJsonString(json, "name");
	assert(content.getName() == name);

	auto itr = _knownModules.find(name);
	if (itr == _knownModules.end())
	{
		auto module = std::make_shared<Module>(name, std::move(json));
		_knownModules.emplace(std::make_pair(name, std::move(module)));
	}
	else
		itr->second->addJson(std::move(json));
}

void ModulePool::_init(const std::string& directory)
{
	if (const char* env_p = std::getenv("YARAMOD_MODULE_SPEC_PATH"))
	{
		std::stringstream paths;
		paths << env_p;
		for (std::string path; std::getline(paths, path, ':'); )
			_processPath(std::filesystem::path(path));
	}
	else
	{
		if (directory != "")
		{
			bool found_modules = false;
			for (const auto& entry : std::filesystem::directory_iterator(directory))
			{
				bool result = _processPath(entry.path());
				found_modules = found_modules || result;
			}
			if (!found_modules)
				throw ModuleError("Directory '" + directory + "' does not contain single valid module. If you want to use public modules only, set directory=\"\".");
		}
		for (const auto& content : _module_list.list)
			_processModuleContent(content);
	}
}

}
