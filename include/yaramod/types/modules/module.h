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
 * Class representing features of module.
 * Every module has to provide its features to state what must hold for it to be loaded.
 */
enum ImportFeatures
{
	Basic = 0x01,          // 001 - such module is always loaded
	AvastOnly = 0x02,      // 010 - such module is loaded when Avast specified
	VirusTotalOnly = 0x04, // 100 - such module is loaded when VirusTotal specified
	Avast = Basic | AvastOnly,           // 011 - specification which will load all basic and Avast-specific modules
	VirusTotal = Basic | VirusTotalOnly, // 101 - specification which will load all basic and VirusTotal-specific modules
	All = Avast | VirusTotal             // 111 - specification which will load all modules
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
	Module(const std::string& name, ImportFeatures features);
	/// @}

	/// @name Destructor
	/// @{
	virtual ~Module();
	/// @}

	/// @name Pure virtual initialization method
	/// @{
	virtual bool initialize(ImportFeatures features) = 0;
	/// @}

	/// @name Getter methods
	/// @{
	const std::string& getName() const;
	const std::shared_ptr<StructureSymbol>& getStructure() const;
	ImportFeatures getFeatures() const;
	/// @}

	/// @name Detection methods
	/// @{
	bool isInitialized() const;
	/// @}

protected:
	std::string _name; ///< Name of the module
	std::shared_ptr<StructureSymbol> _structure; ///< Structure of the module
	ImportFeatures _needed_features; ///< Specifies when this module can be loaded: 
};

}
