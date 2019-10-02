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

#define FMT_HEADER_ONLY 1

// Uncomment for debugging
// #define POG_DEBUG 1

#include <pog/pog.h>

#include "yaramod/yaramod_error.h"
#include "yaramod/parser/lexer.h"
#include "yaramod/types/hex_string.h"
#include "yaramod/types/symbol.h"
#include "yaramod/types/yara_file.h"
#include "yaramod/yy/yy_parser.hpp"

namespace yaramod {

using RegexpRangePair = std::pair<std::optional<std::uint64_t>, std::optional<std::uint64_t>>;

// Value is the type of all tokens produced by POG parser. Both token and rule actions return Value. The rule action parameters are also Values.
class Value
{
public:
	using Variant = std::variant<
		std::string, //0
		int,
		bool, //2
		std::optional<TokenIt>,
		Rule, //4
		std::vector<Meta>,
		std::shared_ptr<Rule::StringsTrie>, //6
		std::pair<std::uint32_t, std::vector<TokenIt>>,
		Literal, //8
		Expression::Ptr,
		std::vector<Expression::Ptr>, //10
		std::vector<TokenIt>,
		std::vector<std::shared_ptr<HexStringUnit>>, //12
		std::shared_ptr<HexStringUnit>,
		std::vector<std::shared_ptr<HexString>>, //14
		std::shared_ptr<String>,
		std::shared_ptr<RegexpUnit>, //16
		std::vector<std::shared_ptr<RegexpUnit>>,
		TokenIt, //18
		RegexpRangePair
	>;

	/// @name Constructors
	/// @{
	Value( const std::string& v ) : _value(v) {}
	Value( std::string&& v ) : _value( std::move(v) ) {}
	Value( int v ) : _value(v) {}
	Value( bool v ) : _value(v) {}
	Value( std::optional<TokenIt> v ) : _value(v) {}
	Value( TokenIt v ) : _value(v) {}
	Value( std::vector<Meta>&& v ) : _value(std::move(v)) {}
	Value( std::shared_ptr<Rule::StringsTrie>&& v ) : _value(std::move(v)) {}
	Value( std::pair<std::uint32_t, std::vector<TokenIt>>&& v ) : _value(std::move(v)) {}
	Value( Literal&& v ) : _value(std::move(v)) {}
	Value( Expression::Ptr&& v ) : _value(std::move(v)) {}
	Value( std::vector<Expression::Ptr>&& v ) : _value(std::move(v)) {}
	Value( std::vector<TokenIt>&& v ) : _value(std::move(v)) {}
	Value( std::vector<std::shared_ptr<HexStringUnit>>&& v ) : _value(std::move(v)) {}
	Value( std::shared_ptr<HexStringUnit>&& v ) : _value(std::move(v)) {}
	Value( std::vector<std::shared_ptr<HexString>>&& v ) : _value(std::move(v)) {}
	Value( std::shared_ptr<String>&& v ) : _value(std::move(v)) {}
	Value( std::shared_ptr<RegexpUnit>&& v ) : _value(std::move(v)) {}
	Value( std::vector<std::shared_ptr<RegexpUnit>>&& v) : _value(std::move(v)) {}
	Value( RegexpRangePair&& v ) : _value(std::move(v)) {}
	Value() = default;
	/// @}


	/// @name Getter methods
	/// @{
	const std::string& getString() const
	{
		return getValue<std::string>();
	}
	int getInt() const
	{
		return getValue<int>();
	}
	bool getBool() const
	{
		return getValue<bool>();
	}
	TokenIt getTokenIt() const {
		return getValue<TokenIt>();
	}
	std::optional<TokenIt> getOptionalTokenIt() const
	{
		return getValue<std::optional<TokenIt>>();
	}
	const Rule& getRule() const
	{
		return getValue<Rule>();
	}
	std::vector<Meta>&& getMetas()
	{
		return std::move(moveValue<std::vector<Meta>>());
	}
	std::shared_ptr<Rule::StringsTrie>&& getStringsTrie()
	{
		return std::move(moveValue<std::shared_ptr<Rule::StringsTrie>>());
	}
	std::pair<std::uint32_t, std::vector<TokenIt>>&& getStringMods()
	{
		return std::move(moveValue<std::pair<std::uint32_t, std::vector<TokenIt>>>());
	}
	const Literal& getLiteral() const
	{
		return getValue<Literal>();
	}
	Expression::Ptr getExpression() const
	{
		return getValue<Expression::Ptr>();
	}
	std::vector<Expression::Ptr>&& getMultipleExpressions()
	{
		return std::move(moveValue<std::vector<Expression::Ptr>>());
	}
	std::vector<TokenIt>&& getMultipleTokenIt()
	{
		return std::move(moveValue<std::vector<TokenIt>>());
	}
	std::vector<std::shared_ptr<HexStringUnit>>&& getMultipleHexUnits()
	{
		return std::move(moveValue<std::vector<std::shared_ptr<HexStringUnit>>>());
	}
	std::shared_ptr<HexStringUnit>&& getHexUnit()
	{
		return std::move(moveValue<std::shared_ptr<HexStringUnit>>());
	}
	std::vector<std::shared_ptr<HexString>>&& getMultipleHexStrings()
	{
		return std::move(moveValue<std::vector<std::shared_ptr<HexString>>>());
	}
	std::shared_ptr<String>&& getYaramodString()
	{
		return std::move(moveValue<std::shared_ptr<String>>());
	}
	std::shared_ptr<RegexpUnit>&& getRegexpUnit()
	{
		return std::move(moveValue<std::shared_ptr<RegexpUnit>>());
	}
	std::vector<std::shared_ptr<RegexpUnit>>&& getMultipleRegexpUnits()
	{
		return std::move(moveValue<std::vector<std::shared_ptr<RegexpUnit>>>());
	}
	RegexpRangePair&& getRegexpRangePair()
	{
		return std::move(moveValue<RegexpRangePair>());
	}
	/// @}

protected:
	template<typename T>
	const T& getValue() const
	{
		try
      {
         return std::get<T>(_value);
      }
      catch (std::bad_variant_access& exp)
      {
         std::cerr << "Called Value.getValue() with incompatible type. Actual index is '" << _value.index() << "'" << std::endl << exp.what() << std::endl;
         std::cerr << "Call: '" << __PRETTY_FUNCTION__ << "'" << std::endl;
         assert(false && "Called getValue<T>() with incompatible type T.");
      }
	}
	template< typename T>
	T&& moveValue()
	{
		try
      {
         return std::move(std::get<T>(std::move(_value)));
      }
      catch (std::bad_variant_access& exp)
      {
          std::cerr << "Called Value.moveValue() with incompatible type. Actual index is '" << _value.index() << "'" << std::endl << exp.what() << std::endl;
         std::cerr << __PRETTY_FUNCTION__ << std::endl;
         assert(false && "Called getValue<T>() with incompatible type T.");
      }
	}

private:
	Variant _value;
};

class ParserDriver;

class PogParser
{
public:
	PogParser(ParserDriver& driver);
	void defineTokens();
	void defineGrammar();
	void enter_state(const std::string& state);
	bool prepareParser();
	void includeFile();
	void parse();
	bool sectionStrings() const { return _sectionStrings; };
	void sectionStrings(bool new_value/*, const std::string& msg = ""*/) {
		// if(new_value)
		// 	std::cerr << std::endl << "Set _sectionStrings=true, '" << msg << "'" << std::endl << std::endl;
		// else
		// 	std::cerr << std::endl << "Set _sectionStrings=false, '" << msg << "'" << std::endl << std::endl;
		_sectionStrings = new_value;
	};

	void setInput(std::istream* input) { _input = input; };
private:
	template<typename... Args> TokenIt emplace_back(Args&&... args);

	std::string _strLiteral; ///< Currently processed string literal.
	std::string _indent;
	std::string _comment;
	std::string _regexpClass; ///< Currently processed regular expression class.
	pog::Parser<Value> _parser;
	ParserDriver& _driver;
	std::istream* _input;
	bool _sectionStrings = false;
};

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
	friend class PogParser;

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
	PogParser _pog_parser; ///< pog parser
	yy::location _loc; ///< Location

	std::stack<std::shared_ptr<TokenStream>> _tokenStreams;
	std::vector<TokenIt> _comments;
	std::string _tmp_comment; //TODO: deleto - only for lexer

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
