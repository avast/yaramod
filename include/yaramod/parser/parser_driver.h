/**
 * @file src/parser/parser_driver.h
 * @brief Declaration of class ParserDriver.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

#include <fstream>
#include <memory>
#include <unordered_map>
#include <limits.h>

#include <pegtl/tao/pegtl.hpp>

#include "yaramod/builder/yara_rule_builder.h"
#include "yaramod/parser/lexer.h"
#include "yaramod/types/symbol.h"
#include "yaramod/types/yara_file.h"
#include "yaramod/yy/yy_parser.hpp"

namespace pgl = TAO_PEGTL_NAMESPACE;

namespace yaramod {

namespace gr { //this namespace is to minimize 'using namespace pgl' scope

   using namespace pgl;

   struct _number : plus< pgl::digit > {};
   struct _word : plus< sor< alnum, one<'='>, string<'/','"'>, one<'_'> > > {};
   struct _space : star< one<' '> > {};
   struct indent : seq< TAO_PEGTL_STRING("    ") > {};

   struct rule_name : _word {};
   struct tag : _word {};

   struct meta_string_value : star< ranges< 'a', 'z', 'A', 'Z', '0', '9', ' '> > {};
   struct meta_uint_value : _number{};
   struct meta_negate_int_value : _number{};
   struct meta_hex_uint_value : seq< one<'0'>, one<'x'>, plus< ranges< '0', '9', 'a','f', 'A', 'F' > > >{};
   struct meta_number_value : sor< seq< one<'-'>, meta_negate_int_value >, meta_hex_uint_value, meta_uint_value > {};
   struct meta_bool_value : sor< TAO_PEGTL_STRING("true"), TAO_PEGTL_STRING("false") > {};
   struct meta_value : sor< seq< one<'"'>, meta_string_value, one<'"'> >, meta_number_value, meta_bool_value > {};
   struct meta_key : star< ranges< 'a', 'z', 'A', 'Z', '_'> > {};
   struct meta_entry : seq< indent, indent, meta_key, TAO_PEGTL_STRING(" = "), meta_value, eol > {};
   struct meta : seq< indent, TAO_PEGTL_STRING("meta:"), eol, plus< meta_entry >  > {};

   struct strings_modifier : seq< one< ' ' >, sor< TAO_PEGTL_STRING("ascii"), TAO_PEGTL_STRING("fullword"), TAO_PEGTL_STRING("nocase"), TAO_PEGTL_STRING("wide") > > {};
   struct slash : seq< plus< one< '\\' > >, pgl::any > {};
   struct strings_value : until< at< one< '"' > >, sor< slash, pgl::any > > {};
   struct strings_key : seq< one< '$' >, ranges< 'a', 'z' >, _number > {};    //$?<cislo>
   struct strings_entry : seq< indent, indent, strings_key, TAO_PEGTL_STRING(" = \""), strings_value, one<'"'>, star< strings_modifier >, opt< eol > > {};
   struct strings : seq< indent, TAO_PEGTL_STRING("strings:"), eol, plus< strings_entry > > {};


   struct condition_line : until< eol, pgl::any > {};
   struct condition_entry : seq< indent, indent, condition_line > {};
   struct condition : seq< indent, TAO_PEGTL_STRING("condition:"), eol, plus< condition_entry > > {};

   struct end_of_rule : plus< eolf > {};

   struct grammar : star<
   seq< star<eol>,
   TAO_PEGTL_STRING("rule "), rule_name, _space,
   sor< eol, seq< _space, one<':'>, plus< seq< _space, tag > >, _space,  opt< eol > > >,
   one< '{' >, eol,
   meta,
   opt< strings >,
   condition,
   one< '}' >,
   end_of_rule >
   >
   {};


   struct token
   {
      enum yytokentype
      {
         END = 258,
         RANGE = 259,
         DOT = 260,
         LT = 261,
         GT = 262,
         LE = 263,
         GE = 264,
         EQ = 265,
         NEQ = 266,
         SHIFT_LEFT = 267,
         SHIFT_RIGHT = 268,
         MINUS = 269,
         PLUS = 270,
         MULTIPLY = 271,
         DIVIDE = 272,
         MODULO = 273,
         BITWISE_XOR = 274,
         BITWISE_AND = 275,
         BITWISE_OR = 276,
         BITWISE_NOT = 277,
         LP = 278,
         RP = 279,
         LCB = 280,
         RCB = 281,
         ASSIGN = 282,
         COLON = 283,
         COMMA = 284,
         PRIVATE = 285,
         GLOBAL = 286,
         RULE = 287,
         META = 288,
         STRINGS = 289,
         CONDITION = 290,
         ASCII = 291,
         NOCASE = 292,
         WIDE = 293,
         FULLWORD = 294,
         XOR = 295,
         BOOL_TRUE = 296,
         BOOL_FALSE = 297,
         IMPORT_MODULE = 298,
         NOT = 299,
         AND = 300,
         OR = 301,
         ALL = 302,
         ANY = 303,
         OF = 304,
         THEM = 305,
         FOR = 306,
         ENTRYPOINT = 307,
         OP_AT = 308,
         OP_IN = 309,
         FILESIZE = 310,
         CONTAINS = 311,
         MATCHES = 312,
         SLASH = 313,
         STRING_LITERAL = 314,
         INTEGER = 315,
         DOUBLE = 316,
         STRING_ID = 317,
         STRING_ID_WILDCARD = 318,
         STRING_LENGTH = 319,
         STRING_OFFSET = 320,
         STRING_COUNT = 321,
         ID = 322,
         INTEGER_FUNCTION = 323,
         HEX_OR = 324,
         LSQB = 325,
         RSQB = 326,
         HEX_WILDCARD = 327,
         DASH = 328,
         HEX_NIBBLE = 329,
         HEX_INTEGER = 330,
         REGEXP_OR = 331,
         REGEXP_ITER = 332,
         REGEXP_PITER = 333,
         REGEXP_OPTIONAL = 334,
         REGEXP_START_OF_LINE = 335,
         REGEXP_END_OF_LINE = 336,
         REGEXP_ANY_CHAR = 337,
         REGEXP_WORD_CHAR = 338,
         REGEXP_NON_WORD_CHAR = 339,
         REGEXP_SPACE = 340,
         REGEXP_NON_SPACE = 341,
         REGEXP_DIGIT = 342,
         REGEXP_NON_DIGIT = 343,
         REGEXP_WORD_BOUNDARY = 344,
         REGEXP_NON_WORD_BOUNDARY = 345,
         REGEXP_CHAR = 346,
         REGEXP_RANGE = 347,
         REGEXP_CLASS = 348,
         UNARY_MINUS = 349,
         INVALID = 16384
      };

      static yytokentype type( const std::string& str ) {
         if(str == " ascii")
            return token::ASCII;
         if(str == " wide")
            return token::WIDE;
         if(str == " nocase")
            return token::NOCASE;
         if(str == " fullword")
            return token::FULLWORD;
         return token::INVALID;
      }
   };

   template< typename Rule >
   struct action {};



} //namespace gr
/*
class Parser {

public:

   void includeStream(std::unique_ptr< std::istream >&& input) { //nahrada lexer::includeFile
      streams.push(std::move(input));
   }

   void includeStream(const std::string& source_file) {
      auto ptr = std::make_unique< std::ifstream >( source_file, std::ifstream::in );
      streams.push(std::move(ptr));
      current_stream_id++;
   }



};
*/

/**
 * Represents error during parsing.
 */
class ParserError : public std::exception
{
public:
	ParserError(const std::string& errorMsg) : _errorMsg(errorMsg) {}
	ParserError(const ParserError&) = default;

	const std::string& getErrorMessage() const noexcept
	{
		return _errorMsg;
	}

	virtual const char* what() const noexcept override
	{
		return _errorMsg.c_str();
	}

private:
	std::string _errorMsg;
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
	template< typename Rule >
   friend struct gr::action;

public:
	/// @name Constructors
	/// @{
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
	/// @}

protected:
	std::istream* currentStream();

	/// @name Methods for handling includes
	/// @{
	bool includeFile(const std::string& includePath);
	bool includeEnd();
	/// @}

	/// @name Methods for handling rules
	/// @{
	bool ruleExists(const std::string& name) const;
	void addRule(Rule&& rule);
	void finishRule();
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

	/// @name Method for handling anonymous strings
	/// @{
	bool isAnonymousStringId(const std::string& stringId) const;
	std::string generateAnonymousStringPseudoId();
	/// @}

private:
	bool isAlreadyIncluded(const std::string& includePath);
	bool includeFileImpl(const std::string& includePath);

	ParserMode _mode; ///< Parser mode.

	//yy::Lexer _lexer; ///< Flex lexer //TODO:delete
	//yy::Parser _parser; ///< Bison parser //TODO:delete
	yy::location _loc; ///< Location

	YaraRuleBuilder builder;
   size_t max_size = UINT_MAX; //-1
   int current_stream = -1;
   std::istream* initial_stream = nullptr;

	std::string meta_key;

	std::vector<std::unique_ptr<std::ifstream>> _includedFiles; ///< Stack of included files
	std::vector<std::string> _includedFileNames; ///< Stack of included file names
	std::vector<yy::location> _includedFileLocs; ///< Stack of included file locations
	std::unordered_set<std::string> _includedFilesCache; ///< Cache of already included files

	bool _valid; ///< Validity
	std::string _filePath; ///< File path if parsing from file
	std::ifstream _inputFile; ///< Input file or stream

	YaraFile _file; ///< Parsed file

	std::weak_ptr<Rule::StringsTrie> _currentStrings; ///< Context storage of current strings trie
	bool _stringLoop; ///< Context storage of for loop indicator
	std::unordered_map<std::string, std::shared_ptr<Symbol>> _localSymbols; ///< Context storage of local symbols

	std::uint64_t _startOfRule; ///< Holds the line number where the last parsed rule starts
	std::uint64_t _anonStringCounter; ///< Internal counter for generating pseudo identifiers of anonymous strings
};

}
