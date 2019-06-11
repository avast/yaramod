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
#include <unordered_map>
#include <variant>

#include <pegtl/tao/pegtl.hpp>
#include <pegtl/tao/pegtl/contrib/parse_tree.hpp>


#include "yaramod/builder/yara_hex_string_builder.h"
#include "yaramod/builder/yara_rule_builder.h"
#include "yaramod/yaramod_error.h"
#include "yaramod/parser/lexer.h"
#include "yaramod/types/hex_string.h"
#include "yaramod/types/symbol.h"
#include "yaramod/types/yara_file.h"
#include "yaramod/yy/yy_parser.hpp"

namespace pgl = TAO_PEGTL_NAMESPACE;

namespace yaramod {

/**
 * Represents error during parsing.
 */
class ParserError : public YaramodError{
public:
	ParserError(const std::string& errorMsg)
		: YaramodError(errorMsg)
	{
	}
	ParserError(const ParserError&) = default;
};

/**
 * Represents type of parsed tokens.
 */
enum Tokentype
   {
   	RULE_NAME = 1,
   	TAG = 2,
   	RULE_END = 3,
   	FILE_END = 4,
      HEX_ALT = 6,
      HEX_NORMAL = 7,
      HEX_WILDCARD_FULL = 8,
      HEX_WILDCARD_LOW = 9,
      HEX_WILDCARD_HIGH = 10,
      HEX_JUMP_VARYING = 11,
      HEX_JUMP_VARYING_RANGE = 12,
      HEX_JUMP_RANGE = 13,
      HEX_JUMP_FIXED = 14,
      HEX_LEFT_BRACKET = 15,
      HEX_RIGHT_BRACKET = 16,


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
      LSQB = 325,
      RSQB = 326,
      DASH = 328,
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
      META_KEY = 288,
      META_VALUE = 289,
      STRING_KEY = 290,
      PLAIN_STRING_VALUE = 291,



      INVALID = 16384
   };

/**
 * Class representing tokens that YARA rules consist of.
 */
struct Token
{

   Token(Tokentype type, int value, pgl::position position)
   	: type(type)
   	, value(value)
   	, position(position)
   {
   }

   Token(Tokentype type, uint value, pgl::position position)
   	: type(type)
   	, value(value)
   	, position(position)
   {
   }

   Token(Tokentype type, bool value, pgl::position position)
   	: type(type)
   	, value(value)
   	, position(position)
   {
   }

   Token(Tokentype type, int64_t value, pgl::position position)
   	: type(type)
   	, value(value)
   	, position(position)
   {
   }

   Token(Tokentype type, const std::string& value, pgl::position position)
   	: type(type)
   	, value(value)
   	, position(position)
   {
   }

   Token(const Token& other) = default;

   Token(Token&& other) = default;

   friend std::ostream& operator<<(std::ostream& os, const Token& token) {
   	os << "[" << token.type << ":";
   	std::visit(
      [&os](auto&& v)
      	{
	         if constexpr(std::is_same_v< decltype(v), std::string& >)
	            os << "'"<< v <<"'";
	         else
	            os << v;
         },
         token.value
 		);
   	return os << "; " << token.position << "]";
 	}

	Tokentype type;
	std::variant<int, uint, int64_t,  bool, std::string> value;
	pgl::position position;
};

namespace gr { //this namespace is to minimize 'using namespace pgl' scope

   using namespace pgl;

   struct comment : sor<
   				seq< TAO_PEGTL_STRING("//"), until< at< eolf >, pgl::any > >,
   				seq< TAO_PEGTL_STRING("/*"), until< at< one<'*'>, one<'/'> > >, TAO_PEGTL_STRING("*/") >
   				> {};
   struct _number : plus< pgl::digit > {};
   struct _identificator : plus< sor< pgl::digit, alnum, one<'_'> > > {};
   struct _word : plus< sor< alnum, one<'='>, string<'/','"'>, one<'_'> > > {};
   struct ws : one< ' ', '\t' > {};
   struct ws_enter : sor< one< ' ', '\t', '\n', '\b'> , eol > {};
   struct opt_space : star< ws > {};
   struct opt_space_enter : star< ws_enter > {};

   struct rule_name : _word {};
   struct tag : _word {};
   struct line : eol {};

   struct meta_string_value : star< ranges< 'a', 'z', 'A', 'Z', '0', '9', ' '> > {};
   struct meta_uint_value : _number{};
   struct meta_negate_int_value : _number{};
   struct meta_hex_uint_value : seq< one<'0'>, one<'x'>, plus< ranges< '0', '9', 'a', 'f', 'A', 'F' > > >{};
   struct meta_number_value : sor< seq< one<'-'>, meta_negate_int_value >, meta_hex_uint_value, meta_uint_value > {};
   struct meta_bool_value : sor< TAO_PEGTL_STRING("true"), TAO_PEGTL_STRING("false") > {};
   struct meta_value : sor< seq< one<'"'>, meta_string_value, one<'"'> >, meta_number_value, meta_bool_value > {};
   struct meta_key : star< ranges< 'a', 'z', 'A', 'Z', '_'> > {};
   struct meta_entry : seq< opt_space_enter, meta_key, TAO_PEGTL_STRING(" = "), meta_value, eol > {};
   struct meta : seq< opt_space_enter, TAO_PEGTL_STRING("meta:"), eol, star< meta_entry >  > {};

   struct slash : seq< plus< one< '\\' > >, pgl::any > {};


   struct hex_literal : ranges< 'a', 'f', 'A', 'F', '0', '9' > {};
   struct hex_normal : seq< hex_literal, hex_literal > {};
   struct hex_wildcard_high : seq< one<'?'>, hex_literal > {};
   struct hex_wildcard_low : seq< hex_literal, one<'?'> > {};
   struct hex_wildcard_full : seq< one<'?'>, one<'?'> > {};
   struct hex_jump_varying : TAO_PEGTL_STRING("[-]") {};

   struct hex_jump_varying_range : seq< one<'['>, _number, one<'-'>, one<']'> > {};
   struct hex_jump_range : seq< one<'['>, _number, one<'-'>, _number, one<']'> > {};
   struct hex_jump_fixed : seq< one<'['>, _number, one<']'> > {};

   struct hex_atom : sor< hex_normal, hex_wildcard_full, hex_wildcard_high, hex_wildcard_low, hex_jump_varying, hex_jump_varying_range, hex_jump_range, hex_jump_fixed > {};
   struct hex_atom_space : seq< hex_atom, opt_space_enter > {};
   struct hex_atom_group : plus< hex_atom_space > {};

   struct hex_comp;
   struct hex_comp_after_alt;
   struct hex_left_bracket : one<'('> {};
   struct hex_righ_bracket : one<')'> {};
   struct hex_brackets : seq< opt_space_enter, hex_left_bracket, hex_comp, opt_space_enter, hex_righ_bracket > {};
   struct hex_alt : seq< opt_space_enter, one<'|'>, opt_space_enter, hex_comp_after_alt > {};
   struct hex_comp_after_alt : sor<
   				seq< hex_brackets, opt_space_enter, opt< hex_comp_after_alt > >,
   				seq< opt_space_enter, hex_atom_group, opt< hex_comp_after_alt > >
   				> {};
	struct hex_comp : sor<
   				seq< hex_brackets, opt_space_enter, hex_comp >,
   				seq< opt_space_enter, hex_atom_group, hex_comp >,
   				plus< hex_alt >,
   				opt_space_enter
   				> {};
	struct hex_comp_start : must<
					one<'{'>,
					opt_space_enter,
					sor<
	   				seq< hex_brackets, opt_space_enter, hex_comp >,
	   				seq< opt_space_enter, hex_atom_group, hex_comp >
						>,
					opt_space_enter,
					one<'}'> > {};

	struct hex_strings_value : seq< opt_space, until< at< one<'}'> >, pgl::any > > {};
	struct hex_strings_entry : seq< one< '{' >, hex_strings_value, one<'}'> > {};

	struct strings_modifier_ascii : TAO_PEGTL_STRING("ascii") {};
	struct strings_modifier_fullword : TAO_PEGTL_STRING("fullword") {};
	struct strings_modifier_nocase : TAO_PEGTL_STRING("nocase") {};
	struct strings_modifier_wide : TAO_PEGTL_STRING("wide") {};
   struct strings_modifier : sor< strings_modifier_ascii, strings_modifier_fullword, strings_modifier_nocase, strings_modifier_wide > {};
   struct plain_strings_value : until< at< one< '"' > >, sor< slash, pgl::any > > {};
   struct plain_strings_entry : seq< one<'"'>, plain_strings_value, one<'"'>, star< seq< opt_space, strings_modifier > > > {};

   struct strings_key : seq< one< '$' >, _identificator > {};
   struct strings_entry : seq< opt_space, strings_key, TAO_PEGTL_STRING(" = "), sor< plain_strings_entry, hex_strings_entry >, opt< eol > > {};
   struct strings : seq< opt_space, TAO_PEGTL_STRING("strings:"), eol, plus< strings_entry > > {};

   // condition must read all lines until '}'.
   struct condition_true : seq< TAO_PEGTL_STRING("true"), opt_space_enter > {};
   struct condition_part : seq< plus< not_at< one< '}' > >, not_at< eolf >, pgl::any >, eol > {};
   struct condition_last_part : seq< plus< not_at< one< '}' > >, not_at< eolf >, pgl::any >, one< '}' > > {};
   struct condition_line :  seq< condition_true >   {};
   struct condition_entry : seq< opt_space, condition_line > {};
   struct condition : seq< opt_space, TAO_PEGTL_STRING("condition:"), opt_space_enter, plus< condition_entry > > {};

   struct end_of_rule : one<'}'> {};
   struct end_of_file : opt< eolf > {};

   struct rule : seq<
	   	opt_space_enter,
	   	TAO_PEGTL_STRING("rule"), opt_space, must< rule_name >, opt_space,
		   sor< line,
		   	seq<
		   		opt_space, one<':'>,
		   		plus< seq< opt_space, tag > >,
		   		opt_space, opt< line >
	   		>,
	   		opt_space
   		>,
   		one< '{' >, line,
   		opt< meta >,
   		opt< strings >,
   		condition,
   		end_of_rule
		> {};

   struct grammar :
   must<
	   star< rule >,
	   end_of_file
		> {};




   template< typename Rule >
   struct action {};

  	YaraHexStringBuilder parse_hex_tree( pgl::parse_tree::node* root, std::vector< Token >& tokens );
/*
   template< typename Rule >
   struct hex_selector : std::false_type {};
   template<> struct hex_selector< hex_brackets > : std::true_type {}; //arity 3,
   template<> struct hex_selector< hex_left_bracket > : std::true_type {}; //leaf,
   template<> struct hex_selector< hex_righ_bracket > : std::true_type {}; //leaf,
   template<> struct hex_selector< hex_alt > : std::true_type {}; //non-leaf
   template<> struct hex_selector< hex_atom_group > : std::true_type {}; //non-leaf
   template<> struct hex_selector< hex_normal > : std::true_type {}; //leaf
   template<> struct hex_selector< _number > : std::true_type {}; //leaf
   template<> struct hex_selector< hex_wildcard_full > : std::true_type {}; //leaf
   template<> struct hex_selector< hex_wildcard_high > : std::true_type {}; //arity 1
   template<> struct hex_selector< hex_wildcard_low > : std::true_type {}; //arity 1
   template<> struct hex_selector< hex_jump_varying > : std::true_type {}; //leaf
   template<> struct hex_selector< hex_jump_varying_range > : std::true_type {}; //arity 1
   template<> struct hex_selector< hex_jump_range > : std::true_type {}; //arity 2
   template<> struct hex_selector< hex_jump_fixed > : std::true_type {}; //arity 1
*/
	template< typename Rule >
   using hex_selector = pgl::parse_tree::selector< Rule,
   	pgl::parse_tree::store_content::on<
      hex_brackets,
      hex_left_bracket,
      hex_righ_bracket,
      hex_alt,
      hex_atom_group,
      hex_normal,
      _number,
      hex_wildcard_full,
      hex_wildcard_high,
      hex_wildcard_low,
      hex_jump_varying,
      hex_jump_varying_range,
      hex_jump_range,
		hex_jump_fixed > >;

   template< typename Rule >
	struct my_control : tao::pegtl::normal< Rule >
	{
	   static const std::string error_message;

	   template< typename Input, typename... States >
	   static void raise( const Input& in, States&&... )
	   {
	      throw tao::pegtl::parse_error( error_message, in );
	   }
	};

} //namespace gr




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
	std::vector< yaramod::Token > tokens;

	/// @name Methods for handling includes
	/// @{
	bool includeFile(const std::string& includePath);
	bool includeEnd();
	/// @}

	/// @name Methods for handling rules
	/// @{
	bool ruleExists(const std::string& name) const;
	void addRule(Rule&& rule);
	void addRule(std::unique_ptr<Rule>&& rule);
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
	bool hasRuleWithName(const std::string& name) const;
	bool includeFileImpl(const std::string& includePath);

	ParserMode _mode; ///< Parser mode.

	//yy::Lexer _lexer; ///< Flex lexer //TODO:delete
	//yy::Parser _parser; ///< Bison parser //TODO:delete
	yy::location _loc; ///< Location

	YaraRuleBuilder builder;
//	YaraHexStringBuilder hex_builder;
   size_t max_size = UINT_MAX; //-1
   int current_stream = -1;
   std::istream* initial_stream = nullptr;

	std::string meta_key;
	std::string str_key;
	std::string plain_str_value;
	std::string hex_str_value;
	uint32_t str_modifiers = 0u;
	int hex_jump_number1 = -1;
	int hex_jump_number2 = -1;

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
