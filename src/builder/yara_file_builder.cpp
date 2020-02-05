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
 * @param driver optional driver to be used to recheck. The driver will be RESET!
 *
 * @return Built YARA file.
 */
std::unique_ptr<YaraFile> YaraFileBuilder::get(bool recheck, ParserDriver* external_driver)
{
	auto yaraFile = std::make_unique<YaraFile>(std::move(_tokenStream), _import_features);
	yaraFile->addImports(_module_tokens, _modules_pool);
	yaraFile->addRules(_rules);

	_module_tokens.clear();
	_rules.clear();
	_tokenStream = std::make_shared<TokenStream>();

	std::stringstream ss;
	ss << yaraFile->getText();

	if (recheck)
	{
		// Recheck the file by parsing it again
		// We are not able to perform all semantic checks while building so we need to do this
		std::unique_ptr<ParserDriver> driver;
		if (external_driver)
		{
			try
			{
				external_driver->parse(ss);
			}
			catch (const ParserError& err)
			{
				std::stringstream ss;
				ss << "Error: Recheck failed: parser error, parsing \n'" << yaraFile->getText() << "'" << std::endl << err.what() << std::endl;
				throw YaraFileBuilderError(ss.str());
			}
		}
		else
		{
			ParserDriver driver(ImportFeatures::AllCurrent);
			try
			{
				driver.parse(ss);
			}
			catch (const ParserError& err)
			{
				std::stringstream ss;
				ss << "Error: Recheck failed: parser error, parsing \n'" << yaraFile->getText() << "'" << std::endl << err.what() << std::endl;
				throw YaraFileBuilderError(ss.str());
			}
		}
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
	if (!_module_tokens.empty())
	{
		if (!_lastAddedWasImport)
			_tokenStream->emplace_back(NEW_LINE, "\n");
	}
	_tokenStream->emplace_back(TokenType::IMPORT_KEYWORD, "import");
	TokenIt moduleToken = _tokenStream->emplace_back(TokenType::IMPORT_MODULE, moduleName);
	_tokenStream->emplace_back(NEW_LINE, "\n");
	_module_tokens.push_back(moduleToken);
	_lastAddedWasImport = true;
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
	if (!_rules.empty() || _lastAddedWasImport)
		_tokenStream->emplace_back(NEW_LINE, "\n");

	_tokenStream->move_append(rule->getTokenStream());
	_tokenStream->emplace_back(NEW_LINE, "\n");

	_rules.emplace_back(std::move(rule));
	_lastAddedWasImport = false;
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
	if (!_rules.empty() || _lastAddedWasImport)
		_tokenStream->emplace_back(NEW_LINE, "\n");

	_tokenStream->move_append(rule->getTokenStream());
	_tokenStream->emplace_back(NEW_LINE, "\n");
	_rules.emplace_back(rule);
	_lastAddedWasImport = false;
	return *this;
}

}
