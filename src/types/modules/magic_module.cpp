/**
 * @file src/types/modules/magic_module.cpp
 * @brief Implementation of MagicModule.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "yaramod/types/expression.h"
#include "yaramod/types/modules/magic_module.h"
#include "yaramod/types/symbol.h"

namespace yaramod {

/**
 * Constructor.
 */
MagicModule::MagicModule() : Module("magic")
{
}

/**
 * Initializes module structure.
 *
 * @return @c true if success, otherwise @c false.
 */
bool MagicModule::initialize(NeededSymbols needed_symbols)
{
	using Type = Expression::Type;
	(void) needed_symbols;

	auto magicStruct = std::make_shared<StructureSymbol>("magic");
	magicStruct->addAttribute(std::make_shared<FunctionSymbol>("mime_type", Type::String));
	magicStruct->addAttribute(std::make_shared<FunctionSymbol>("type", Type::String));

	_structure = magicStruct;
	return true;
}

}
