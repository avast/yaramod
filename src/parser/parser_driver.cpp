/**
 * @file src/parser/parser_driver.cpp
 * @brief Implementation of class ParserDriver.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <string>

#include <tl-cpputils/filesystem_path.h>
#include <tl-cpputils/string.h>

#include "yaramod/parser/parser_driver.h"

namespace yaramod {

/**
 * Constructor.
 *
 * @param filePath Input file path.
 * @param parserMode Parsing mode.
 */
ParserDriver::ParserDriver(const std::string& filePath, ParserMode parserMode) : _mode(parserMode), _lexer(*this), _parser(*this),
	_loc(nullptr), _valid(true), _filePath(), _inputFile(), _file(), _currentStrings(), _stringLoop(false), _localSymbols()
{
	// Uncomment for debugging
	// See also occurrences of 'debugging' in parser.y to enable it
	//_parser.set_debug_level(1);

	// When creating ParserDriver from real file (not from some stringstream) we need to somehow tell lexer which file to process
	// yy::Lexer is not copyable nor assignable so we need to hack it through includes
	if (!includeFileImpl(filePath))
		_valid = false;
}

/**
 * Constructor.
 *
 * @param input Input stream.
 * @param parserMode Parsing mode.
 */
ParserDriver::ParserDriver(std::istream& input, ParserMode parserMode) : _mode(parserMode), _lexer(*this, &input), _parser(*this),
	_loc(nullptr), _valid(true), _filePath(), _inputFile(), _file(), _currentStrings(), _stringLoop(false), _localSymbols()
{
	// Uncomment for debugging
	// See also occurrences of 'debugging' in parser.y to enable it
	//_parser.set_debug_level(1);
}

/**
 * Returns the lexer.
 *
 * @return Lexer.
 */
yy::Lexer& ParserDriver::getLexer()
{
	return _lexer;
}

/**
 * Returns the parser.
 *
 * @return parser.
 */
yy::Parser& ParserDriver::getParser()
{
	return _parser;
}

/**
 * Returns the location in the file.
 *
 * @return Location.
 */
const yy::location& ParserDriver::getLocation() const
{
	return _loc;
}

/**
 * Returns the result of parsing. The parsed YARA file.
 *
 * @return Parsed YARA file.
 */
YaraFile& ParserDriver::getParsedFile()
{
	return _file;
}

/**
 * Returns the result of parsing. The parsed YARA file.
 *
 * @return Parsed YARA file.
 */
const YaraFile& ParserDriver::getParsedFile() const
{
	return _file;
}

/**
 * Parses the input stream or file.
 *
 * @return @c true if parsing succeeded, otherwise @c false.
 */
bool ParserDriver::parse()
{
	if (!_valid)
		return false;

	return _parser.parse() == 0;
}

/**
 * Returns whether the parser driver is in valid state.
 *
 * @return @c true if valid, otherwise @c false.
 */
bool ParserDriver::isValid() const
{
	return _valid;
}

/**
 * Moves one line further and resets the counter of columns.
 */
void ParserDriver::moveLineLocation()
{
	_loc.lines();
}

/**
 * Moves given number of columns further.
 *
 * @param moveLength Number of columns to move.
 */
void ParserDriver::moveLocation(std::uint64_t moveLength)
{
	_loc.step();
	_loc += moveLength;
}

/**
 * Includes file into input stream as it would be in place of @c include directive.
 *
 * @param includePath Path of file to include.
 *
 * @return @c true if include succeeded, otherwise @c false.
 */
bool ParserDriver::includeFile(const std::string& includePath)
{
	auto totalPath = includePath;
	if (tl_cpputils::FilesystemPath(includePath).isRelative())
	{
		// We are not running ParserDriver from file input, just from some unnamed istream, therefore we need to forbid relative includes from
		// the top of the istream hierarchy
		if (_includedFileNames.empty() && _filePath.empty())
			return false;

		// Take the topmost file path from the stack.
		// This allows us to nest includes forming hierarchy of included files.
		totalPath = tl_cpputils::FilesystemPath(_includedFileNames.back()).getParentPath() +
			tl_cpputils::FilesystemPath::separator() +
			includePath;

		totalPath = tl_cpputils::FilesystemPath(totalPath).getAbsolutePath();
	}

	return includeFileImpl(totalPath);
}

/**
 * Ends the include of the currently included file. This should normally happen when end-of-file is reached.
 * End of include may fail if there are no more files to pop from include stack.
 *
 * @return @c true if end of include succeeded, otherwise @c false.
 */
bool ParserDriver::includeEnd()
{
	if (!_includedFileNames.empty())
		_includedFileNames.pop_back();
	return _lexer.includeEnd();
}

/**
 * Returns whether rule with given name already exists.
 *
 * @param name Name of the rule.
 *
 * @return @c true if exists, @c false otherwise.
 */
bool ParserDriver::ruleExists(const std::string& name) const
{
	return std::any_of(_file.getRules().begin(), _file.getRules().end(),
			[&name](const auto& rule)
			{
				return rule->getName() == name;
			});
}

/**
 * Returns whether string with given identifier already exists in the current rule context.
 *
 * @param id Identifier of the string.
 *
 * @return @c true if exists, otherwise @c false.
 */
bool ParserDriver::stringExists(const std::string& id) const
{
	// Anonymous string references are available only in string-based for loops
	if (isInStringLoop() && id == "$")
		return true;

	auto currentStrings = _currentStrings.lock();
	if (!currentStrings)
		return false;

	// Is wildcard identifier
	if (tl_cpputils::endsWith(id, "*"))
	{
		auto idNonWild = id.substr(0, id.length() - 1);
		return currentStrings->isPrefix(idNonWild);
	}
	else
	{
		std::shared_ptr<String> string;
		return currentStrings->find(id, string);
	}

	return false;
}

/**
 * Sets the current strings trie for the context of the current rule.
 *
 * @param currentStrings Strings trie to set.
 */
void ParserDriver::setCurrentStrings(const std::shared_ptr<Rule::StringsTrie>& currentStrings)
{
	_currentStrings = currentStrings;
}

/**
 * Returns whether parser is in string-based for loop.
 *
 * @return @c true if is in string-based for loop, otherwise @c false.
 */
bool ParserDriver::isInStringLoop() const
{
	return _stringLoop;
}

/**
 * Sets that parser entered string-based for loop.
 */
void ParserDriver::stringLoopEnter()
{
	_stringLoop = true;
}

/**
 * Sets that parser left string-based for loop.
 */
void ParserDriver::stringLoopLeave()
{
	_stringLoop = false;
}

/**
 * Finds the symbol with the given name. It first searches in local symbols and then in global symbols.
 *
 * @param name Symbol name.
 *
 * @return Valid symbol if found, @c nullptr otherwise.
 */
std::shared_ptr<Symbol> ParserDriver::findSymbol(const std::string& name) const
{
	auto itr = _localSymbols.find(name);
	if (itr != _localSymbols.end())
		return itr->second;

	return _file.findSymbol(name);
}

/**
 * Adds the symbol to the local symbol table. If symbol with that name already exists, method fails.
 *
 * @param symbol Symbol to add.
 *
 * @return @c true if symbol was successfully added, otherwise @c false.
 */
bool ParserDriver::addLocalSymbol(const std::shared_ptr<Symbol>& symbol)
{
	if (findSymbol(symbol->getName()))
		return false;

	_localSymbols[symbol->getName()] = symbol;
	return true;
}

/**
 * Removes symbol with the given name from the local symbol table.
 *
 * @param name Name of the symbol to remove.
 */
void ParserDriver::removeLocalSymbol(const std::string& name)
{
	_localSymbols.erase(name);
}

bool ParserDriver::isAlreadyIncluded(const std::string& includePath)
{
	return _includedFilesCache.find(tl_cpputils::FilesystemPath(includePath).getAbsolutePath()) != _includedFilesCache.end();
}

bool ParserDriver::includeFileImpl(const std::string& includePath)
{
	if (_mode == ParserMode::IncludeGuarded && isAlreadyIncluded(includePath))
		return true;

	// We need to allocate ifstreams dynamically because they are not copyable and we need to store them
	// in vector to prolong their lifetime because of flex.
	auto includedFile = std::make_unique<std::ifstream>(includePath);
	if (!includedFile->is_open())
		return false;

	_lexer.includeFile(includedFile.get());
	_includedFiles.push_back(std::move(includedFile));
	_includedFileNames.push_back(includePath);
	_includedFilesCache.emplace(tl_cpputils::FilesystemPath(includePath).getAbsolutePath());
	return true;
}

}
