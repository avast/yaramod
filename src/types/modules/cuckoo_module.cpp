/**
 * @file src/types/modules/cuckoo_module.cpp
 * @brief Implementation of CuckooModule.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "yaramod/types/expression.h"
#include "yaramod/types/modules/cuckoo_module.h"
#include "yaramod/types/symbol.h"

namespace yaramod {

/**
 * Constructor.
 */
CuckooModule::CuckooModule() : Module("cuckoo")
{
}

/**
 * Initializes module structure.
 *
 * @return @c true if success, otherwise @c false.
 */
bool CuckooModule::initialize()
{
	using Type = Expression::Type;

	auto cuckooStruct = std::make_shared<StructureSymbol>("cuckoo");
	auto networkStruct = std::make_shared<StructureSymbol>("network");
	cuckooStruct->addAttribute(networkStruct);
	networkStruct->addAttribute(std::make_shared<FunctionSymbol>("dns_lookup", Type::Int, Type::Regexp));
	networkStruct->addAttribute(std::make_shared<FunctionSymbol>("http_get", Type::Int, Type::Regexp));
	networkStruct->addAttribute(std::make_shared<FunctionSymbol>("http_post", Type::Int, Type::Regexp));
	networkStruct->addAttribute(std::make_shared<FunctionSymbol>("http_request", Type::Int, Type::Regexp));

	auto registryStruct = std::make_shared<StructureSymbol>("registry");
	cuckooStruct->addAttribute(registryStruct);
	registryStruct->addAttribute(std::make_shared<FunctionSymbol>("key_access", Type::Int, Type::Regexp));
	registryStruct->addAttribute(std::make_shared<FunctionSymbol>("key_read", Type::Int, Type::Regexp));
	registryStruct->addAttribute(std::make_shared<FunctionSymbol>("key_write", Type::Int, Type::Regexp));
	registryStruct->addAttribute(std::make_shared<FunctionSymbol>("key_delete", Type::Int, Type::Regexp));
	registryStruct->addAttribute(std::make_shared<FunctionSymbol>("key_value_access", Type::Int, Type::Regexp, Type::Regexp));

	auto filesystemStruct = std::make_shared<StructureSymbol>("filesystem");
	cuckooStruct->addAttribute(filesystemStruct);
	filesystemStruct->addAttribute(std::make_shared<FunctionSymbol>("file_access", Type::Int, Type::Regexp));
	filesystemStruct->addAttribute(std::make_shared<FunctionSymbol>("file_read", Type::Int, Type::Regexp));
	filesystemStruct->addAttribute(std::make_shared<FunctionSymbol>("file_write", Type::Int, Type::Regexp));
	filesystemStruct->addAttribute(std::make_shared<FunctionSymbol>("file_delete", Type::Int, Type::Regexp));
	filesystemStruct->addAttribute(std::make_shared<FunctionSymbol>("pipe", Type::Int, Type::Regexp));
	filesystemStruct->addAttribute(std::make_shared<FunctionSymbol>("mailslot", Type::Int, Type::Regexp));

	auto syncStruct = std::make_shared<StructureSymbol>("sync");
	cuckooStruct->addAttribute(syncStruct);
	syncStruct->addAttribute(std::make_shared<FunctionSymbol>("mutex", Type::Int, Type::Regexp));
	syncStruct->addAttribute(std::make_shared<FunctionSymbol>("event", Type::Int, Type::Regexp));
	syncStruct->addAttribute(std::make_shared<FunctionSymbol>("semaphore", Type::Int, Type::Regexp));
	syncStruct->addAttribute(std::make_shared<FunctionSymbol>("atom", Type::Int, Type::Regexp));
	syncStruct->addAttribute(std::make_shared<FunctionSymbol>("section", Type::Int, Type::Regexp));
	syncStruct->addAttribute(std::make_shared<FunctionSymbol>("job", Type::Int, Type::Regexp));
	syncStruct->addAttribute(std::make_shared<FunctionSymbol>("timer", Type::Int, Type::Regexp));

	auto processStruct = std::make_shared<StructureSymbol>("process");
	cuckooStruct->addAttribute(processStruct);
	processStruct->addAttribute(std::make_shared<FunctionSymbol>("executed_command", Type::Int, Type::Regexp));
	processStruct->addAttribute(std::make_shared<FunctionSymbol>("created_service", Type::Int, Type::Regexp));
	processStruct->addAttribute(std::make_shared<FunctionSymbol>("started_service", Type::Int, Type::Regexp));
	processStruct->addAttribute(std::make_shared<FunctionSymbol>("resolved_api", Type::Int, Type::Regexp));

	auto signatureStruct = std::make_shared<StructureSymbol>("signature");
	cuckooStruct->addAttribute(signatureStruct);
	signatureStruct->addAttribute(std::make_shared<FunctionSymbol>("name", Type::Int, Type::Regexp));

	_structure = cuckooStruct;
	return true;
}

}
