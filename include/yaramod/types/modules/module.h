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
 * Class determines wheter to load avast-specific and VirusTotal-specific symbols in the module.
 */
class NeededSymbols
{
public:
	NeededSymbols(bool avast_specific, bool vt_specific)
		: _avast_specific(avast_specific)
		, _vt_specific(vt_specific)
	{
	}
	bool avast_specific() const { return _avast_specific; }
	bool vt_specific() const { return _vt_specific; }

private:
	bool _avast_specific;
	bool _vt_specific;
};

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
	virtual bool initialize(NeededSymbols needed_symbols) = 0;
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
	static std::shared_ptr<Module> load(const std::string& name, NeededSymbols needed_symbols);
	/// @}

protected:
	std::string _name; ///< Name of the module
	std::shared_ptr<StructureSymbol> _structure; ///< Structure of the module
};

}
