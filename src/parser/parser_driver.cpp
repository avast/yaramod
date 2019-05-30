/**
 * @file src/parser/parser_driver.cpp
 * @brief Implementation of class ParserDriver.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <string>

#include "yaramod/parser/parser_driver.h"
#include "yaramod/utils/filesystem.h"
#include "yaramod/types/expressions.h"

namespace yaramod {

namespace gr {

	template<>
   struct action< rule_name >
   {
      template< typename Input >
      static void apply(const Input& in, ParserDriver& d)
      {
      	std::cout << "Rule name: " << in.string() << "'" << std::endl;
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
//         std::cout << "'Saving h.meta_key= " << in.string() << "'" << std::endl;
         d.meta_key = in.string();
      }
   };

   template<>
   struct action< meta_string_value >
   {
      template< typename Input >
      static void apply(const Input& in, ParserDriver& d)
      {
//         std::cout << "'Matched meta_string_value action with '" << in.string() << "'" << std::endl;
         d.builder.withStringMeta(d.meta_key, in.string());
      }
   };

   template<>
   struct action< meta_uint_value >
   {
      template< typename Input >
      static void apply(const Input& in, ParserDriver& d)
      {
//         std::cout << "'Matched meta_uint_value action with '" << in.string() << "'" << std::endl;
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
//         std::cout << "'Matched meta_negate_int_value action with '" << in.string() << "'" << std::endl;
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
//         std::cout << "'Matched meta_hex_uint_value action with '" << in.string() << "'" << std::endl;
         int64_t meta_value = std::stoi(in.string(), nullptr, 16);
         d.builder.withHexIntMeta(d.meta_key, meta_value);
      }
   };

   template<>
   struct action< meta_bool_value >
   {
      template< typename Input >
      static void apply(const Input& in, ParserDriver& d)
      {
//         std::cout << "'Matched meta_bool_value action with '" << in.string() << "'" << std::endl;
         if(in.string() == "true")
            d.builder.withBoolMeta(d.meta_key, true);
         else if(in.string() == "false")
            d.builder.withBoolMeta(d.meta_key, false);
         else
         	assert(false && "meta_bool_value value must match 'true' or 'false' only");
         d.meta_key = "";
      }
   };

   template<>
   struct action< condition_true >
   {
   	template< typename Input >
   	static void apply(const Input& /*unused*/, ParserDriver& d)
   	{
//   		std::cout << "Condition true called" << std::endl;
   		d.builder.withCondition( std::make_unique< BoolLiteralExpression >(true) );
   	}
   };
/*
   template<>
   struct action< condition_line >
   {
      template< typename Input >
      static void apply(const Input& in, const ParserDriver& )
      {
         std::cout << "Matched condition_line with '" << in.string() << "'" << std::endl;
      }
   };
*/
   template<>
   struct action< condition >
   {
      template< typename Input >
      static void apply(const Input& in, const ParserDriver& /*unused*/)
      {
         std::cout << "Matched condition with '" << in.string() << "'" << std::endl;
//        state.condition.push_back(in.string());
      }
   };

   template<>
   struct action< plain_strings_value >
   {
      template< typename Input >
      static void apply(const Input& in, ParserDriver& d)
      {
         d.plain_str_value = in.string();
      }
   };

   template<>
   struct action< plain_strings_entry >
   {
      template< typename Input >
      static void apply(const Input& in, ParserDriver& d)
      {
         std::cout << "SSS Matched plain_strings_entry with '" << in.string() << "'"
                   << "   SSS d.str_modifiers =  " << d.str_modifiers << " key=" << d.str_key << std::endl;
         d.builder.withPlainString(d.str_key, d.plain_str_value, d.str_modifiers);
         d.str_key = "";
         d.plain_str_value = "";
         d.str_modifiers = 0u;
      }
   };

   template<>
   struct action< hex_literal >
   {
      template< typename Input >
      static void apply(const Input& in, const ParserDriver&)
      {
         std::cout << "Matched hex_literal with '" << in.string() << "'" << std::endl;
      }
   };

   template<>
   struct action< hex_normal >
   {
   	template< typename Input >
   	static void apply(const Input& in, ParserDriver& d)
   	{
   		std::cout << "Matched hex_normal with '" << in.string() << "'" << std::endl;
   		const auto hex_n = std::stoi(in.string(), nullptr, 16);
   		d.hex_builder.add(hex_n);
//   		std::cout << "Result " << hex_n << std::endl;
   	}
   };

   template<>
   struct action< hex_wildcard_high >
   {
   	template< typename Input >
   	static void apply(const Input& in, ParserDriver& d)
   	{
//   		std::cout << "Matched hex_wildcard_high with '" << in.string() << "'" << std::endl;
   		assert(in.string().length() == 2);
   		const auto hex_high = std::stoi(in.string().substr(1,1), nullptr, 16);
   		assert(hex_high <= 16);
   		d.hex_builder.add(wildcardHigh(hex_high));
//   		std::cout << "Result " << hex_high << std::endl;
   	}
   };

   template<>
   struct action< hex_wildcard_low >
   {
   	template< typename Input >
   	static void apply(const Input& in, ParserDriver& d)
   	{
//   		std::cout << "Matched hex_wildcard_low with '" << in.string() << "'" << std::endl;
   		assert(in.string().length() == 2);
   		const auto hex_low = std::stoi(in.string().substr(0,1), nullptr, 16);
   		assert(hex_low <= 16);
   		d.hex_builder.add(wildcardLow(hex_low));
//   		std::cout << "Result " << hex_low << std::endl;
   	}
   };

   template<>
   struct action< hex_wildcard_full >
   {
   	template< typename Input >
   	static void apply(const Input& /*unused*/, ParserDriver& d)
   	{
//   		std::cout << "Matched hex_wildcard_full with '" << in.string() << "'" << std::endl;
   		d.hex_builder.add(wildcard());
     	}
   };

   template<>
   struct action< hex_jump_varying >
   {
   	template< typename Input >
   	static void apply(const Input& /*unused*/, ParserDriver& d)
   	{
//   		std::cout << "Matched hex_jump_varying with '" << in.string() << "'" << std::endl;
   		d.hex_builder.add(jumpVarying());
   	}
   };

   template<>
   struct action< hex_jump_number1 >
   {
   	template< typename Input >
   	static void apply(const Input& in, ParserDriver& d) { d.hex_jump_number1 = std::stoi(in.string()); }
   };

   template<>
   struct action< hex_jump_number2 >
   {
   	template< typename Input >
   	static void apply(const Input& in, ParserDriver& d) { d.hex_jump_number2 = std::stoi(in.string()); }
   };

   template<>
   struct action< hex_jump_varying_range >
   {
   	template< typename Input >
   	static void apply(const Input& /*unused*/, ParserDriver& d)
   	{
//   		std::cout << "Matched hex_jump_varying_range with '" << in.string() << "'" << std::endl;
   		d.hex_builder.add(jumpVaryingRange(d.hex_jump_number1));
   		d.hex_jump_number1 = -1;
   	}
   };

   template<>
   struct action< hex_jump_range >
   {
      template< typename Input >
      static void apply(const Input& /*unused*/, ParserDriver& d)
      {
//         std::cout << "Matched hex_jump_range with '" << in.string() << "'" << std::endl;
      	d.hex_builder.add(jumpRange(d.hex_jump_number1, d.hex_jump_number2));
      	d.hex_jump_number1 = d.hex_jump_number2 = -1;
      }
   };

   template<>
   struct action< hex_jump_fixed >
   {
      template< typename Input >
      static void apply(const Input& /*unused*/, ParserDriver& d)
      {
//         std::cout << "Matched hex_jump_fixed with '" << in.string() << "'" << std::endl;
         d.hex_builder.add(jumpFixed(d.hex_jump_number1));
         d.hex_jump_number1 = -1;
      }
   };


   template<>
   struct action< hex_atom >
   {
      template< typename Input >
      static void apply(const Input& in, const ParserDriver&)
      {
         std::cout << "Matched hex_atom with '" << in.string() << "'" << std::endl;
      }
   };

   template<>
   struct action< hex_comp_alt_brackets >
   {
      template< typename Input >
      static void apply(const Input& in, const ParserDriver&)
      {
         std::cout << "Matched hex_atom_alt_brackets with '" << in.string() << "'" << std::endl;
      }
   };

   template<>
   struct action< hex_comp_alt_no_brackets >
   {
      template< typename Input >
      static void apply(const Input& in, const ParserDriver&)
      {
         std::cout << "Matched hex_comp_alt_no_brackets with '" << in.string() << "'" << std::endl;
      }
   };

   template<>
   struct action< helperC >
   {
      template< typename Input >
      static void apply(const Input& in, const ParserDriver&)
      {
         std::cout << "Matched helperC with '" << in.string() << "'" << std::endl;
      }
   };

   template<>
   struct action< hex_comp >
   {
      template< typename Input >
      static void apply(const Input& in, const ParserDriver&)
      {
         std::cout << "Matched hex_comp with '" << in.string() << "'" << std::endl;
      }
   };


   template<>
   struct action< hex_strings_value >
   {
      template< typename Input >
      static void apply(const Input& in, ParserDriver& d)
      {
      	(void) in;
      	auto hex_string = d.hex_builder.get();
      	d.builder.withHexString(d.str_key, hex_string);
      	d.str_key = "";
      }
   };

   template<>
   struct action< hex_strings_entry >
   {
      template< typename Input >
      static void apply(const Input& in, ParserDriver& d)
      {
         std::cout << "XXX Matched hex_strings_entry with '" << in.string() << "'"
                   << "XXX d.str_modifiers =  " << d.str_modifiers << " key=" << d.str_key << std::endl;
         d.str_modifiers = 0u;
      }
   };

   template<>
   struct action< strings_modifier >
   {
      template< typename Input >
      static void apply(const Input& in, ParserDriver& d)
      {
         std::cout << "Matched strings_modifier with '" << in.string() << "'" << std::endl;
         d.str_modifiers |= token::type(in.string());
         std::cout << "Changed d.str_modifiers to " << d.str_modifiers << std::endl;
      }
   };

   template<>
   struct action< strings_key >
   {
      template< typename Input >
      static void apply(const Input& in, ParserDriver& d)
      {
         std::cout << "Matched strings_key with '" << in.string() << "'" << std::endl;
         d.str_key = in.string();
      }
   };

   template<>
   struct action< strings >
   {
      template< typename Input >
      static void apply(const Input& in, const ParserDriver& /*unused*/)
      {
         std::cout << "Matched strings with '" << in.string() << "'" << std::endl;
      }
   };

   template<>
   struct action< end_of_rule >
   {
      template< typename Input >
      static void apply(const Input& in, ParserDriver& d)
      {
      	std::cout << "Rule was finished!" << std::endl;
      	(void) in;
         d.finishRule();
      }
   };

   template<>
   struct action< end_of_file >
   {
      template< typename Input >
      static void apply(const Input&, const ParserDriver&)
      {
      	std::cout << "TADA!" << std::endl;
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

	return result == 1;
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
	std::cout << "ParserDriver::addRule called" << std::endl;
	addRule(std::make_unique<Rule>(std::move(rule)));
}

/**
 * Adds the rule into the YARA file and properly sets up its location.
 *
 * @param rule Rule to add.
 */
void ParserDriver::addRule(std::unique_ptr<Rule>&& rule)
{
	std::cout << "ParserDriver::addRule called" << std::endl;
	if (!_includedFileNames.empty())
		rule->setLocation(_includedFileNames.back(), _startOfRule);
	bool success = _parsed_rule_names.insert(rule->getName()).second;
	if(!success)
		throw ParserError("Error at <TODO location>: Redefinition of rule <TODO name>");
	else
		_file.addRule(std::move(rule));
}

void ParserDriver::finishRule()
{
	std::cout << "ParserDriver::finishRule called" << std::endl;
   std::unique_ptr<Rule> rule = builder.get();
   std::cerr << "Rule: " << rule->getText() << std::endl;
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

bool ParserDriver::hasRuleWithName(const std::string& name) const
{
	return _parsed_rule_names.count(name) != 0;
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
