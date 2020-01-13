/**
 * @file src/types/modules/time_module.cpp
 * @brief Implementation of TimeModule.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "yaramod/types/expression.h"
#include "yaramod/types/modules/time_module.h"
#include "yaramod/types/symbol.h"

namespace yaramod {

/**
 * Constructor.
 */
TimeModule::TimeModule() : Module("time")
{
}

/**
 * Initializes module structure.
 *
 * @return @c true if success, otherwise @c false.
 */
bool TimeModule::initialize(NeededSymbols needed_symbols)
{
	using Type = Expression::Type;
	(void) needed_symbols;

	auto timeStruct = std::make_shared<StructureSymbol>("time");

	timeStruct->addAttribute(std::make_shared<FunctionSymbol>("now", Type::Int));

	_structure = timeStruct;
	return true;
}

}
