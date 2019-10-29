/**
 * @file src/builder/yara_file_builder.h
 * @brief Declaration of class YaraFileBuilder.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

#include <memory>
#include <vector>

#include "yaramod/parser/parser_driver.h"
#include "yaramod/types/yara_file.h"

namespace yaramod {

/**
 * Class representing builder of YARA files. You use this builder
 * to specify what you want in your YARA file and then you can obtain
 * your YARA file by calling method @c get. As soon as @c get is called,
 * builder resets to default state and does not contain any data from
 * the previous build process.
 */
class YaraFileBuilder
{
public:
	/// @name Constructors
	/// @{
	YaraFileBuilder()
		: _tokenStream(std::make_shared<TokenStream>())
	{
	}
	/// @}

	/// @name Build method
	/// @{
	std::unique_ptr<YaraFile> get(bool recheck = true, ParserDriver* external_driver = nullptr);
	/// @}

	/// @name Building methods
	/// @{
	YaraFileBuilder& withModule(const std::string& moduleName);
	YaraFileBuilder& withRule(Rule&& rule);
	YaraFileBuilder& withRule(std::unique_ptr<Rule>&& rule);
	YaraFileBuilder& withRule(const std::shared_ptr<Rule>& rule);
	/// @}

private:
	bool _lastAddedWasImport = false; ///< Flag to determine newlines
	std::shared_ptr<TokenStream> _tokenStream; ///< Tokens storage
	std::vector<TokenIt> _modules; ///< Modules
	std::vector<std::shared_ptr<Rule>> _rules; ///< Rules
};

}
