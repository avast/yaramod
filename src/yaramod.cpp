/**
 * @file src/yaramod.cpp
 * @brief Implementation of yaramod interface.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "yaramod/yaramod.h"

namespace yaramod {

namespace {

template <typename Input, typename Output>
std::unique_ptr<YaraFile> parseImpl(Input&& input, Output&& output, ParserMode parserMode)
{
	ParserDriver driver(std::forward<Input>(input), std::forward<Output>(output), parserMode);
	if (!driver.isValid())
		return nullptr;

	std::unique_ptr<YaraFile> result;
	if (driver.parse())
		result = std::make_unique<YaraFile>(std::move(driver.getParsedFile()));

	return result;
}

}

/**
 * Parses file at given path. Errors are printed to the standard output stream.
 *
 * @param filePath Path to the file.
 * @param parserMode Parsing mode.
 *
 * @return Valid @c YaraFile instance if parsing succeeded, otherwise @c nullptr.
 */
std::unique_ptr<YaraFile> parseFile(const std::string& filePath, ParserMode parserMode)
{
	return parseImpl(filePath, std::cerr, parserMode);
}

/**
 * Parses file at given path and prints errors to the file at specific path.
 *
 * @param filePath Path to the file.
 * @param errorLogPath Path where to print errors.
 * @param parserMode Parsing mode.
 *
 * @return Valid @c YaraFile instance if parsing succeeded, otherwise @c nullptr.
 */
std::unique_ptr<YaraFile> parseFile(const std::string& filePath, const std::string& errorLogPath, ParserMode parserMode)
{
	std::ofstream errorLog(errorLogPath);
	if (!errorLog.is_open())
		return nullptr;

	return parseImpl(filePath, errorLog, parserMode);
}

/**
 * Parses file at given path and prints errors to the specified output stream.
 *
 * @param filePath Path to the file.
 * @param errorLogStream Stream where to print errors.
 * @param parserMode Parsing mode.
 *
 * @return Valid @c YaraFile instance if parsing succeeded, otherwise @c nullptr.
 */
std::unique_ptr<YaraFile> parseFile(const std::string& filePath, std::ostream& errorLogStream, ParserMode parserMode)
{
	return parseImpl(filePath, errorLogStream, parserMode);
}

/**
 * Parses input stream. Errors are printed to the standard output stream.
 *
 * @param inputStream Input stream.
 * @param parserMode Parsing mode.
 *
 * @return Valid @c YaraFile instance if parsing succeeded, otherwise @c nullptr.
 */
std::unique_ptr<YaraFile> parseStream(std::istream& inputStream, ParserMode parserMode)
{
	return parseImpl(inputStream, std::cerr, parserMode);
}

/**
 * Parses input stream and prints errors to the file at specific path.
 *
 * @param inputStream Input stream.
 * @param errorLogPath Path where to print errors.
 * @param parserMode Parsing mode.
 *
 * @return Valid @c YaraFile instance if parsing succeeded, otherwise @c nullptr.
 */
std::unique_ptr<YaraFile> parseStream(std::istream& inputStream, const std::string& errorLogPath, ParserMode parserMode)
{
	std::ofstream errorLog(errorLogPath);
	if (!errorLog.is_open())
		return nullptr;

	return parseImpl(inputStream, errorLog, parserMode);
}

/**
 * Parses input stream and prints errors to the specified output stream.
 *
 * @param inputStream Input stream.
 * @param errorLogStream Stream where to print errors.
 * @param parserMode Parsing mode.
 *
 * @return Valid @c YaraFile instance if parsing succeeded, otherwise @c nullptr.
 */
std::unique_ptr<YaraFile> parseStream(std::istream& inputStream, std::ostream& errorLogStream, ParserMode parserMode)
{
	return parseImpl(inputStream, errorLogStream, parserMode);
}

}
