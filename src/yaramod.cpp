/**
 * @file src/yaramod.cpp
 * @brief Implementation of yaramod interface.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "yaramod/yaramod.h"

namespace yaramod {

namespace {

template <typename Input>
std::unique_ptr<YaraFile> parseImpl(Input&& input, ParserMode parserMode)
{
	ParserDriver driver(std::forward<Input>(input), parserMode);
	if (!driver.isValid())
		return nullptr;

	std::unique_ptr<YaraFile> result;
	if (driver.parse())
		result = std::make_unique<YaraFile>(std::move(driver.getParsedFile()));

	return result;
}

}

/**
 * Parses file at given path.
 *
 * @param filePath Path to the file.
 * @param parserMode Parsing mode.
 *
 * @return Valid @c YaraFile instance if parsing succeeded, otherwise @c nullptr.
 */
std::unique_ptr<YaraFile> parseFile(const std::string& filePath, ParserMode parserMode)
{
	return parseImpl(filePath, parserMode);
}

/**
 * Parses input stream.
 *
 * @param inputStream Input stream.
 * @param parserMode Parsing mode.
 *
 * @return Valid @c YaraFile instance if parsing succeeded, otherwise @c nullptr.
 */
std::unique_ptr<YaraFile> parseStream(std::istream& inputStream, ParserMode parserMode)
{
	return parseImpl(inputStream, parserMode);
}

}
