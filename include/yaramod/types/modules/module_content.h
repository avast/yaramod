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
	explicit ModuleContent(const std::string& name)
		: _name(name), _content()
	{
	}

	ModuleContent(const std::string& name, std::string&& content)
		: _name(name), _content(std::move(content))
	{
	}
	/// @}

	/// @name Getter methods
	/// @{
	const std::string& getName() const { return _name; }
	const std::string& getContent() const { return _content; }
	/// @}

	/// @name Setter methods
	/// @{
	void setContent(std::string&& content) { _content += std::move(content); }
	/// @}

private:
	std::string _name; ///< Name of the module
	std::string _content; ///< The content of the module in JSON
};

} //namespace yaramod
