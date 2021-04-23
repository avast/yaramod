/**
 * @file src/types/modules/module_content.h
 * @brief Declaration of class ModuleContent.
 * @copyright (c) 2021 Avast Software, licensed under the MIT license
 */

#pragma once

#include <sstream>
#include <string>

#include "yaramod/utils/json.h"

namespace yaramod {

/**
 * Class holding contents of importable Module.
 */
class ModuleContent
{
public:
	/// @name Constructors
	/// @{
	ModuleContent(const std::string& name, std::initializer_list<char> fileContent)
		: _name(name)
	{
		std::stringstream ss;
		for (const auto& c : fileContent)
			ss << c;
		_content = ss.str();
	}
	/// @}

	/// @name Getter methods
	/// @{
	const std::string& getName() const { return _name; }
	const std::string& getContent() const { return _content; }
	/// @}

private:
	std::string _name; ///< Name of the module
	std::string _content; ///< The content of the module in JSON
};

} //namespace yaramod
