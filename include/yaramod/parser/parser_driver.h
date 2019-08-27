/**
 * @file src/parser/parser_driver.h
 * @brief Declaration of class ParserDriver.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

#include <fstream>
#include <limits.h>
#include <memory>
#include <set>
#include <stack>
#include <unordered_map>

#include "yaramod/yaramod_error.h"
#include "yaramod/parser/lexer.h"
#include "yaramod/types/hex_string.h"
#include "yaramod/types/symbol.h"
#include "yaramod/types/yara_file.h"
#include "yaramod/yy/yy_parser.hpp"

namespace yaramod {

/**
 * Represents error during parsing.
 */
class ParserError : public YaramodError
{
public:
	ParserError(const std::string& errorMsg)
		: YaramodError(errorMsg)
	{
	}
	ParserError(const ParserError&) = default;
};

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
  	ParserDriver() = delete;
	explicit ParserDriver(const std::string& filePath, ParserMode parserMode = ParserMode::Regular);
	explicit ParserDriver(std::istream& input, ParserMode parserMode = ParserMode::Regular);
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

	/// @name Methods for handling comments
   /// @{
   void addComment(TokenIt comment);
   /// @}

protected:
	/// @name Methods for handling includes
	/// @{
	bool includeFile(const std::string& includePath, std::shared_ptr<TokenStream> substream);
	bool includeEnd();
	/// @}

	/// @name Methods for handling rules
	/// @{
	bool ruleExists(const std::string& name) const;
	void addRule(Rule&& rule);
	void addRule(std::unique_ptr<Rule>&& rule);
	void markStartOfRule();
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

	/// @name Methods for handling anonymous strings
	/// @{
	bool isAnonymousStringId(const std::string& stringId) const;
	std::string generateAnonymousStringPseudoId();
	/// @}

	/// @name Methods for handling token streams
	/// @{
	std::shared_ptr<TokenStream> currentStream() const { return _tokenStreams.top(); }
	/// @}

private:
	bool isAlreadyIncluded(const std::string& includePath);
	bool hasRuleWithName(const std::string& name) const;
	bool includeFileImpl(const std::string& includePath, std::shared_ptr<TokenStream> substream);

	ParserMode _mode; ///< Parser mode.

	yy::Lexer _lexer; ///< Flex lexer
	yy::Parser _parser; ///< Bison parser
	yy::location _loc; ///< Location

	std::stack<std::shared_ptr<TokenStream>> _tokenStreams;
	std::vector<TokenIt> _comments;
	std::optional<TokenIt> _tmp_token;
   std::string _tmp_comment;

	std::vector<std::unique_ptr<std::ifstream>> _includedFiles; ///< Stack of included files
	std::vector<std::string> _includedFileNames; ///< Stack of included file names
	std::vector<yy::location> _includedFileLocs; ///< Stack of included file locations
	std::unordered_set<std::string> _includedFilesCache; ///< Cache of already included files

	bool _valid; ///< Validity
	std::string _filePath; ///< File path if parsing from file
	std::ifstream _inputFile; ///< Input file or stream

	YaraFile _file; ///< Parsed file
	std::set<std::string> _parsed_rule_names;

	std::weak_ptr<Rule::StringsTrie> _currentStrings; ///< Context storage of current strings trie
	bool _stringLoop; ///< Context storage of for loop indicator
	std::unordered_map<std::string, std::shared_ptr<Symbol>> _localSymbols; ///< Context storage of local symbols

	std::uint64_t _startOfRule; ///< Holds the line number where the last parsed rule starts
	std::uint64_t _anonStringCounter; ///< Internal counter for generating pseudo identifiers of anonymous strings
};

} // namespace yaramod
