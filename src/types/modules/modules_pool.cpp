/**
 * @file src/types/modules/modules_pool.cpp
 * @brief Implementation of CustomModule.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <sstream>

#include "yaramod/types/modules/modules_pool.h"


namespace yaramod {

using Json = nlohmann::json;

bool ModulesPool::_processPath(std::filesystem::path p)
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

bool ModulesPool::_processModuleContent(const ModuleContent& content)
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

bool ModulesPool::_init()
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

ModulesPool::ModulesPool()
{
	_init();

	// Initializes all modules
	for (auto itr = _knownModules.begin(); itr != _knownModules.end(); ++itr)
		itr->second->initialize();
}

}
