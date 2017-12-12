/**
 * @file src/parser/parser_driver.h
 * @brief Declaration of class ParserDriver.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

#include <fstream>
#include <memory>
#include <unordered_map>

#include "yaramod/parser/lexer.h"
#include "yaramod/types/symbol.h"
#include "yaramod/types/yara_file.h"
#include "yy_parser.hpp"

namespace yaramod {

/**
 * Specifies different parsing modes.
 */
enum class ParserMode
{
	Regular, ///< In this mode, parser behaves like regular YARA parser
	IncludeGuarded ///< Parser provides protection against inclusion of the same file multiple times
};

/**
 * Class representing handler of parser and communication channel between lexer and parser.
 * It also serves as context storage for parsing.
 */
class ParserDriver
{
	friend class yy::Lexer;
	friend class yy::Parser;

public:
	/// @name Constructors
	/// @{
	explicit ParserDriver(const std::string& filePath, ParserMode parserMode = ParserMode::Regular);
	explicit ParserDriver(const std::string& filePath, std::ostream& error, ParserMode parserMode = ParserMode::Regular);
	explicit ParserDriver(std::istream& input, ParserMode parserMode = ParserMode::Regular);
	explicit ParserDriver(std::istream& input, std::ostream& error, ParserMode parserMode = ParserMode::Regular);
	/// @}

	/// @name Destructor
	/// @{
	~ParserDriver() = default;
	/// @}

	/// @name Getter methods
	/// @{
	yy::Lexer& getLexer();
	yy::Parser& getParser();
	const yy::location& getLocation() const;
	YaraFile& getParsedFile();
	const YaraFile& getParsedFile() const;
	std::ostream& getErrorStream();
	/// @}

	/// @name Parsing methods
	/// @{
	bool parse();
	/// @}

	/// @name Detection methods
	/// @{
	bool isValid() const;
	/// @}

	/// @name Methods for lexer
	/// @{
	void moveLineLocation();
	void moveLocation(std::uint64_t moveLength);
	/// @}

protected:
	/// @name Methods for handling includes
	/// @{
	bool includeFile(const std::string& includePath);
	bool includeEnd();
	/// @}

	/// @name Methods for handling rules
	/// @{
	bool ruleExists(const std::string& name) const;
	/// @}

	/// @name Methods for handling strings
	/// @{
	bool stringExists(const std::string& id) const;
	void setCurrentStrings(const std::shared_ptr<Rule::StringsTrie>& currentStrings);
	/// @}

	/// @name Methods for handling for loops
	/// @{
	bool isInStringLoop() const;
	void stringLoopEnter();
	void stringLoopLeave();
	/// @}

	/// @name Methods for handling symbols
	/// @{
	std::shared_ptr<Symbol> findSymbol(const std::string& name) const;
	bool addLocalSymbol(const std::shared_ptr<Symbol>& symbol);
	void removeLocalSymbol(const std::string& name);
	/// @}

private:
	bool isAlreadyIncluded(const std::string& includePath);
	bool includeFileImpl(const std::string& includePath);

	ParserMode _mode; ///< Parser mode.

	yy::Lexer _lexer; ///< Flex lexer
	yy::Parser _parser; ///< Bison parser
	yy::location _loc; ///< Location
	std::ostream& _error; ///< Error stream

	std::vector<std::unique_ptr<std::ifstream>> _includedFiles; ///< Stack of included files
	std::vector<std::string> _includedFileNames; ///< Stack of included file names
	std::unordered_set<std::string> _includedFilesCache; ///< Cache of already included files

	bool _valid; ///< Validity
	std::string _filePath; ///< File path if parsing from file
	std::ifstream _inputFile; ///< Input file or stream

	YaraFile _file; ///< Parsed file

	std::weak_ptr<Rule::StringsTrie> _currentStrings; ///< Context storage of current strings trie
	bool _stringLoop; ///< Context storage of for loop indicator
	std::unordered_map<std::string, std::shared_ptr<Symbol>> _localSymbols; ///< Context storage of local symbols
};

}
