/**
 * @file src/types/modules/module.h
 * @brief Declaration of class Module.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

#include <memory>
#include <string>

#include "yaramod/types/symbols.h"

namespace yaramod {

/**
 * Abstract class representing importable module. Every module
 * has to provide its structure in virtual method @c initialize.
 */
class Module
{
public:
	/// @name Constructors
	/// @{
	Module(const std::string& name);
	/// @}

	/// @name Destructor
	/// @{
	virtual ~Module();
	/// @}

	/// @name Pure virtual initialization method
	/// @{
	virtual bool initialize() = 0;
	/// @}

	/// @name Getter methods
	/// @{
	const std::string& getName() const;
	const std::shared_ptr<StructureSymbol>& getStructure() const;
	/// @}

	/// @name Detection methods
	/// @{
	bool isInitialized() const;
	/// @}

	/// @name Static module loading
	/// @{
	static std::shared_ptr<Module> load(const std::string& name);
	/// @}

protected:
	std::string _name; ///< Name of the module
	std::shared_ptr<StructureSymbol> _structure; ///< Structure of the module
};

}
