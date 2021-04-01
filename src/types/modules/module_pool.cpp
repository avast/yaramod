/**
 * @file src/types/modules/module_pool.cpp
 * @brief Implementation of CustomModule.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <sstream>

#include "yaramod/types/modules/module_pool.h"


namespace yaramod {

using Json = nlohmann::json;

ModulePool::ModulePool()
{
	_init();

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

bool ModulePool::_processModuleContent(const ModuleContent& content)
{
	auto json = readJsonString(content.getContent());
	if (!json.contains("kind") || accessJsonString(json, "kind") != "struct")
		return false;

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

	return true;
}

bool ModulePool::_init()
{
	bool found_modules = false;

	if (const char* env_p = std::getenv("YARAMOD_MODULE_SPEC_PATH"))
	{
		std::stringstream paths;
		paths << env_p;
		for (std::string path; std::getline(paths, path, ':'); )
			found_modules = _processPath(std::filesystem::path(path));
	}
	else
	{
		for (const auto& content : _modules_list.list)
			found_modules = _processModuleContent(content);
	}
	return found_modules;
}

}
