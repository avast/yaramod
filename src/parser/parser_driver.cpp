/**
 * @file src/parser/parser_driver.cpp
 * @brief Implementation of class ParserDriver.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <string>

#include "yaramod/parser/parser_driver.h"
#include "yaramod/utils/filesystem.h"

namespace yaramod {

namespace gr {
	template<>
   struct action< rule_name >
   {
      template< typename Input >
      static void apply(const Input& in, ParserDriver& d)
      {
         d.builder.withName(in.string());
      }
   };

   template<>
   struct action< tag >
   {
      template< typename Input >
      static void apply(const Input& in, ParserDriver& d)
      {
         d.builder.withTag(in.string());
      }
   };

   template<>
   struct action< meta_key >
   {
      template< typename Input >
      static void apply(const Input& in, ParserDriver& d)
      {
         std::cerr << "'Saving h.meta_key= " << in.string() << std::endl;
         d.meta_key = in.string();
      }
   };

   template<>
   struct action< meta_string_value >
   {
      template< typename Input >
      static void apply(const Input& in, ParserDriver& d)
      {
         std::cerr << "'Called meta_string_value action with '" << in.string() << std::endl;
         d.builder.withStringMeta(d.meta_key, in.string());
      }
   };

   template<>
   struct action< meta_uint_value >
   {
      template< typename Input >
      static void apply(const Input& in, ParserDriver& d)
      {
         std::cerr << "'Called meta_uint_value action with '" << in.string() << std::endl;
         int64_t meta_value = std::stoi(in.string());
         d.builder.withUIntMeta(d.meta_key, meta_value);
      }
   };

   template<>
   struct action< meta_negate_int_value >
   {
      template< typename Input >
      static void apply(const Input& in, ParserDriver& d)
      {
         std::cerr << "'Called meta_negate_int_value action with '" << in.string() << std::endl;
         int64_t meta_value = (-1) * std::stoi(in.string());
         d.builder.withIntMeta(d.meta_key, meta_value);
      }
   };

   template<>
   struct action< meta_hex_uint_value >
   {
      template< typename Input >
      static void apply(const Input& in, ParserDriver& d)
      {
         std::cerr << "'Called meta_hex_uint_value action with '" << in.string() << std::endl;
         int64_t meta_value = std::stoi(in.string());
         d.builder.withUIntMeta(d.meta_key, meta_value);
      }
   };

   template<>
   struct action< meta_bool_value >
   {
      template< typename Input >
      static void apply(const Input& in, ParserDriver& d)
      {
         std::cerr << "'Called meta_bool_value action with '" << in.string() << std::endl;
         if(in.string() == "true")
            d.builder.withBoolMeta(d.meta_key, true);
         else if(in.string() == "false")
            d.builder.withBoolMeta(d.meta_key, false);
         else assert(false && "meta_bool_value value must match 'true' or 'false' only");
      }
   };

   template<>
   struct action< condition_line >
   {
      template< typename Input >
      static void apply(const Input& in, const ParserDriver& /*unused*/)
      {
         std::cerr << "Called action condition_line with '" << in.string() << "'" << std::endl;
//        state.condition.push_back(in.string());
      }
   };

   template<>
   struct action< strings_modifier >
   {
      template< typename Input >
      static void apply(const Input& in, const ParserDriver& /*unused*/)
      {
         std::cerr << "Called action strings_modifier with '" << in.string() << "'" << std::endl;
//         state.strings_tokens.back().push_back(token::type(in.string()));
      }
   };

   template<>
   struct action< strings_entry >
   {
      template< typename Input >
      static void apply(const Input& in, const ParserDriver& /*unused*/)
      {
         std::cerr << "Called action strings_entry with '" << in.string() << "'" << std::endl;
      }
   };

   template<>
   struct action< strings_key >
   {
      template< typename Input >
      static void apply(const Input& in, const ParserDriver& /*unused*/)
      {
         std::cerr << "Called action strings_key with '" << in.string() << "'" << std::endl;
//         state.strings_keys.push_back(in.string());
//         state.strings_tokens.emplace_back();
      }
   };

   template<>
   struct action< strings_value >
   {
      template< typename Input >
      static void apply(const Input& in, const ParserDriver& /*unused*/)
      {
         std::cerr << "Called action strings_value with '" << in.string() << "'" << std::endl;
//         state.strings_values.push_back(in.string());
      }
   };

   template<>
   struct action< end_of_rule >
   {
      template< typename Input >
      static void apply(const Input& in, ParserDriver& d)
      {
      	(void) in;
         d.finishRule();
      }
   };
} // namespace gr

/**
 * Constructor.
 *
 * @param filePath Input file path.
 * @param parserMode Parsing mode.
 */
ParserDriver::ParserDriver(const std::string& filePath, ParserMode parserMode) : _mode(parserMode), _loc(nullptr),
   current_stream(0), _valid(true), _filePath(), _inputFile(), _file(), _currentStrings(), _stringLoop(false), _localSymbols(),
	_startOfRule(0), _anonStringCounter(0)
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
ParserDriver::ParserDriver(std::istream& input, ParserMode parserMode) : _mode(parserMode), _loc(nullptr),
	initial_stream(&input), _valid(true), _filePath(), _inputFile(), _file(), _currentStrings(), _stringLoop(false), _localSymbols()
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
//yy::Lexer& ParserDriver::getLexer()
//{
//	return _lexer;
//}

/**
 * Returns the parser.
 *
 * @return parser.
 */
//yy::Parser& ParserDriver::getParser()
//{
//	return _parser;
//}

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


std::istream* ParserDriver::currentStream()
{
	if(initial_stream)
		return initial_stream;
	else
	   return _includedFiles[0].get();
}

/**
 * Parses the input stream or file.
 *
 * @return @c true if parsing succeeded, otherwise @c false.
 */
bool ParserDriver::parse()
{
	//std::cout << "ParserDriver::parse() called" << std::endl;
	if (!_valid)
		return false;

	std::cerr << "ParserDriver::parse called" << std::endl;
   auto stream = currentStream();
   auto input = pgl::istream_input(*stream, max_size, "from_content");

   auto result = pgl::parse< gr::grammar, gr::action >(input, *this);

   if(result)
      std::cerr << "parsing OK" << std::endl;
   else
      std::cerr << "parsing failed" << std::endl;

	return result == 0;
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
	if (pathIsRelative(includePath))
	{
		// We are not running ParserDriver from file input, just from some unnamed istream, therefore we need to forbid relative includes from
		// the top of the istream hierarchy
		if (_includedFileNames.empty() && _filePath.empty())
			return false;

		// Take the topmost file path from the stack.
		// This allows us to nest includes forming hierarchy of included files.
		totalPath = absolutePath(joinPaths(parentPath(_includedFileNames.back()), includePath));
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
	{
		_includedFiles.pop_back();
		_includedFileNames.pop_back();
		_loc = _includedFileLocs.back();
		_includedFileLocs.pop_back();
	}

	//return _lexer.includeEnd();
	return false; //TODO fix this
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
 * Adds the rule into the YARA file and properly sets up its location.
 *
 * @param rule Rule to add.
 */
void ParserDriver::addRule(Rule&& rule)
{
	if (!_includedFileNames.empty())
		rule.setLocation(_includedFileNames.back(), _startOfRule);
	_file.addRule(std::move(rule));
}

void ParserDriver::finishRule()
{
   auto rule = *(builder.get());
   addRule(std::move(rule));
}

/**
 * Marks the line number where the rule starts.
 */
void ParserDriver::markStartOfRule()
{
	_startOfRule = getLocation().end.line;
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
	if (endsWith(id, '*'))
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

/**
 * Indicates whether the string identifier is anonymous string
 * identifier. That means just '$' alone.
 *
 * @param stringId String identifier.
 * @return @c true if identifier of anonymous string, otherwise @c false.
 */
bool ParserDriver::isAnonymousStringId(const std::string& stringId) const
{
	return stringId == "$";
}

/**
 * Generates psuedoidentifier for anonymous string.
 *
 * @return Unique pseudoidentifier.
 */
std::string ParserDriver::generateAnonymousStringPseudoId()
{
	std::ostringstream str;
	str << "anon" << _anonStringCounter++;
	return str.str();
}

bool ParserDriver::isAlreadyIncluded(const std::string& includePath)
{
	return _includedFilesCache.find(absolutePath(includePath)) != _includedFilesCache.end();
}

bool ParserDriver::includeFileImpl(const std::string& includePath)//TODO: upravit
{
	if (_mode == ParserMode::IncludeGuarded && isAlreadyIncluded(includePath))
		return true;

	// We need to allocate ifstreams dynamically because they are not copyable and we need to store them
	// in vector to prolong their lifetime because of flex.
	auto includedFile = std::make_unique<std::ifstream>(includePath);
	if (!includedFile->is_open())
		return false;

	//_lexer.includeFile(includedFile.get());

	_includedFiles.push_back(std::move(includedFile));
	_includedFileNames.push_back(includePath);
	_includedFileLocs.push_back(_loc);
	_includedFilesCache.emplace(absolutePath(includePath));

	// Reset location se we can keep track of line numbers in included files
	_loc.begin.initialize(_loc.begin.filename, 1, 1);
	_loc.end.initialize(_loc.end.filename, 1, 1);
	return true;
}

/*
bool ParserDriver::includeEnd()
{
	// yypop_buffer_state();
	if (!YY_CURRENT_BUFFER)
		return false;

	return true;
}

void ParserDriver::includeFile(std::istream* input)
{
	//vlastni rozhrani kterym loadnu treba jiny file s jinym pravidlem
	//tady mas istream, ted parsuj z neho
	yypush_buffer_state(yy_create_buffer(input, YY_BUF_SIZE));
}
*/
} //namespace yaramod
