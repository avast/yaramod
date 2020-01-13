/**
 * @file src/types/modules/module.cpp
 * @brief Implementation of class Module.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "yaramod/types/modules/module.h"
#include "yaramod/types/modules/modules.h"

namespace yaramod {

namespace {

/**
 * Table of all known modules.
 */
std::unordered_map<std::string, std::shared_ptr<Module>> knownModules =
{
	{ "androguard", std::make_shared<AndroguardModule>() },
	{ "cuckoo",     std::make_shared<CuckooModule>()     },
	{ "dex",        std::make_shared<DexModule>()        },
	{ "dotnet",     std::make_shared<DotnetModule>()     },
	{ "elf",        std::make_shared<ElfModule>()        },
	{ "hash",       std::make_shared<HashModule>()       },
	{ "macho",      std::make_shared<MachoModule>()      },
	{ "magic",      std::make_shared<MagicModule>()      },
	{ "math",       std::make_shared<MathModule>()       },
	{ "pe",         std::make_shared<PeModule>()         },
	{ "phish",      std::make_shared<PhishModule>()      },
	{ "time",       std::make_shared<TimeModule>()       }
};

}

/**
 * Constructor.
 *
 * @param name Name of the module
 */
Module::Module(const std::string& name) : _name(name), _structure()
{
}

/**
 * Destructor.
 */
Module::~Module()
{
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

void Module::reset(const std::string& name)
{
	auto itr = knownModules.find(name);
	if (itr != knownModules.end())
		itr->second->_structure = nullptr;
}

/**
 * Loads the module based on its name from the table of known modules.
 *
 * @param name Name of the module to load
 * @param avastSpecific Determines which symbols to import
 *
 * @return Module if found, @c nullptr otherwise.
 */
std::shared_ptr<Module> Module::load(const std::string& name, bool avastSpecific)
{
	if (!avastSpecific && (name == "androguard" || name == "phish")) // the androguard and phish modules are completely avast-specific
		return nullptr;
	auto itr = knownModules.find(name);
	if (itr == knownModules.end())
		return nullptr;

	// Module haven't been initialized yet, initialize it.
	if (!itr->second->isInitialized())
		itr->second->initialize(avastSpecific);

	return itr->second;
}

}
