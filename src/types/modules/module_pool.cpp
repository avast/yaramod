/**
 * @file src/types/modules/module_pool.cpp
 * @brief Implementation of CustomModule.
 * @copyright (c) 2021 Avast Software, licensed under the MIT license
 */

#include <sstream>
#include <cstdlib>

#include "yaramod/types/modules/module_pool.h"


namespace yaramod {

using Json = nlohmann::json;

ModulePool::ModulePool(Features features, const std::string& directory)
	: _features(features)
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

bool ModulePool::_processPath(fs::path p)
{
	if (p.extension() != ".cpp" && p.extension() != ".json")
		return false;

	auto path = p.string();

	auto json = readJsonFile(path);
	if (!json.contains("kind") || accessJsonString(json, "kind") != "struct")
		return false;

	if (! (_features & Features::Deprecated))
		if (json.contains("deprecated") && accessJsonString(json, "deprecated") == "true")
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
	if (!json.contains("kind") || accessJsonString(json, "kind") != "struct")
		throw ModuleError("Invalid json module: expected \"kind\": \"struct\"");

	if (! (_features & Features::Deprecated))
		if (json.contains("deprecated") && accessJsonString(json, "deprecated") == "true")
			return;

	auto name = accessJsonString(json, "name");
	if (content.getName() != name)
		throw ModuleError("Invalid json module: expected '" + name + "' got '" + content.getName() + "'.");

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
	if (const char* envProperty = std::getenv("YARAMOD_MODULE_SPEC_PATH_EXCLUSIVE"))
	{
		if (std::getenv("YARAMOD_MODULE_SPEC_PATH"))
			throw ModuleError("Error: Both YARAMOD_MODULE_SPEC_PATH and YARAMOD_MODULE_SPEC_PATH_EXCLUSIVE environment properties are set.");
		std::stringstream paths{envProperty};
		for (std::string path; std::getline(paths, path, ':'); )
			_processPath(fs::path(path));
	}
	else
	{
		bool foundModules = false;
		if (const char* envProperty = std::getenv("YARAMOD_MODULE_SPEC_PATH"))
		{
			std::stringstream paths{envProperty};
			for (std::string path; std::getline(paths, path, ':'); )
			{
				bool result = _processPath(fs::path(path));
				foundModules = foundModules || result;
			}
			if (!foundModules)
				throw ModuleError("Could not find any valid module specified in environmental variable YARAMOD_MODULE_SPEC_PATH. Unset or change the variable.");
		}
		if (directory != "")
		{
			for (const auto& entry : fs::directory_iterator(directory))
			{
				bool result = _processPath(entry.path());
				foundModules = foundModules || result;
			}
			if (!foundModules)
				throw ModuleError("Directory '" + directory + "' does not contain single valid module. If you want to use public modules, set directory=\"\".");
		}
		for (const auto& content : _moduleList.list)
			_processModuleContent(content);
	}
}

}
