/**
 * @file src/yaramod.h
 * @brief Declaration of yaramod interface.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#pragma once

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#define YARAMOD_VERSION_MAJOR 3
#define YARAMOD_VERSION_MINOR 16
#define YARAMOD_VERSION_PATCH 0
#define YARAMOD_VERSION_ADDEND ""

#define YARAMOD_VERSION STR(YARAMOD_VERSION_MAJOR) "." STR(YARAMOD_VERSION_MINOR) "." STR(YARAMOD_VERSION_PATCH) YARAMOD_VERSION_ADDEND

#define YARA_SYNTAX_VERSION "4.2"

#include <memory>

#include "yaramod/builder/yara_file_builder.h"
#include "yaramod/parser/parser_driver.h"
#include "yaramod/types/yara_file.h"

namespace yaramod {

class Yaramod
{
public:
	/*
	 * Constructor
	 *
	 * @param features determines iff we want to use aditional Avast-specific symbols or VirusTotal-specific symbols in the imported modules
	 * @param moduleDirectory determines a directory for additional YARA modules to be added
	 */
	Yaramod(Features features = Features::AllCurrent, const std::string& moduleDirectory = "") : _driver(features, moduleDirectory)	{}
	/**
	 * Parses file at given path.
	 *
	 * @param filePath Path to the file.
	 * @param parserMode Parsing mode.
	 *   - Regular -- regular YARA parser
	 *   - IncludeGuarded -- protection against inclusion of the same file multiple times
	 *
	 * @return Valid @c YaraFile instance if parsing succeeded, otherwise @c nullptr.
	 */
	std::unique_ptr<YaraFile> parseFile(const std::string& filePath, ParserMode parserMode = ParserMode::Regular);
	/**
	 * Parses input stream.
	 *
	 * @param inputStream Input stream.
	 * @param parserMode Parsing mode.
	 *   - Regular -- regular YARA parser
	 *   - IncludeGuarded -- protection against inclusion of the same file multiple times
	 *
	 * @return Valid @c YaraFile instance if parsing succeeded, otherwise @c nullptr.
	 */
	std::unique_ptr<YaraFile> parseStream(std::istream& inputStream, ParserMode parserMode = ParserMode::Regular);

	const YaraFile& getParsedFile() const;

	/**
	 * Returns ModulePool used in the parser, which gives information on which modules are available.
	 *
	 * @return Used ModulePool
	 */
	std::map<std::string, Module*> getModules() const;

private:
	ParserDriver _driver;
};

}
