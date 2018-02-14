/**
 * @file src/builder/yara_file_builder.cpp
 * @brief Implementation of class YaraFileBuilder.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "yaramod/builder/yara_file_builder.h"
#include "yaramod/parser/parser_driver.h"

namespace yaramod {

/**
 * Returns the built YARA file and resets the builder back to default state.
 *
 * @param recheck @c true if generated file should be rechecked by parser.
 *
 * @return Built YARA file.
 */
std::unique_ptr<YaraFile> YaraFileBuilder::get(bool recheck)
{
	auto yaraFile = std::make_unique<YaraFile>();
	yaraFile->addImports(_modules);
	yaraFile->addRules(_rules);

	_modules.clear();
	_rules.clear();

	std::stringstream ss;
	ss << yaraFile->getText();

	if (recheck)
	{
		// Recheck the file by parsing it again
		// We are not able to perform all semantic checks while building so we need to do this
		ParserDriver driver(ss);

		try
		{
			driver.parse();
		}
		catch (const ParserError&)
		{
			return nullptr;
		}

		return std::make_unique<YaraFile>(std::move(driver.getParsedFile()));
	}

	return yaraFile;
}

/**
 * Adds module to YARA file.
 *
 * @param moduleName Module name.
 *
 * @return Builder.
 */
YaraFileBuilder& YaraFileBuilder::withModule(const std::string& moduleName)
{
	_modules.push_back(moduleName);
	return *this;
}

/**
 * Adds rule to YARA file.
 *
 * @param rule Rule.
 *
 * @return Builder.
 */
YaraFileBuilder& YaraFileBuilder::withRule(Rule&& rule)
{
	withRule(std::make_unique<Rule>(std::move(rule)));
	return *this;
}

/**
 * Adds rule to YARA file.
 *
 * @param rule Rule.
 *
 * @return Builder.
 */
YaraFileBuilder& YaraFileBuilder::withRule(std::unique_ptr<Rule>&& rule)
{
	_rules.emplace_back(std::move(rule));
	return *this;
}

/**
 * Adds rule to YARA file.
 *
 * @param rule Rule.
 *
 * @return Builder.
 */
YaraFileBuilder& YaraFileBuilder::withRule(const std::shared_ptr<Rule>& rule)
{
	_rules.emplace_back(rule);
	return *this;
}

}
