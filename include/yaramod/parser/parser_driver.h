/**
 * @file src/parser/parser_driver.h
 * @brief Declaration of class ParserDriver.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

#include <climits>
#include <fstream>
#include <memory>
#include <set>
#include <stack>
#include <unordered_map>

#define FMT_HEADER_ONLY 1

// Uncomment for debugging
// #define POG_DEBUG 1

#include <pog/pog.h>

#include "yaramod/utils/trie.h"
#include "yaramod/types/expressions.h"
#include "yaramod/types/hex_string.h"
#include "yaramod/types/hex_string.h"
#include "yaramod/types/token_stream.h"
#include "yaramod/types/meta.h"
#include "yaramod/types/plain_string.h"
#include "yaramod/types/regexp.h"
#include "yaramod/types/rule.h"
#include "yaramod/types/symbol.h"
#include "yaramod/types/yara_file.h"
#include "yaramod/yaramod_error.h"

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
	template <typename T>
	Value(T&& v)
		: _value(std::forward<T>(v))
	{
	}
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

	TokenIt getTokenIt() const
	{
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
	template <typename T>
	const T& getValue() const
	{
		try
		{
			return std::get<T>(_value);
		}
		catch (std::bad_variant_access& exp)
		{
			// Uncomment for debugging
			// std::cerr << "Called Value.getValue() with incompatible type. Actual index is '" << _value.index() << "'" << std::endl << exp.what() << std::endl;
			// std::cerr << "Call: '" << __PRETTY_FUNCTION__ << "'" << std::endl;
			throw YaramodError("Called getValue<T>() with incompatible type T.", exp.what());
		}
	}
	template < typename T>
	T&& moveValue()
	{
		try
		{
			return std::move(std::get<T>(std::move(_value)));
		}
		catch (std::bad_variant_access& exp)
		{
			// Uncomment for debugging
			// std::cerr << "Called Value.moveValue() with incompatible type. Actual index is '" << _value.index() << "'" << std::endl << exp.what() << std::endl;
			// std::cerr << __PRETTY_FUNCTION__ << std::endl;
			throw YaramodError("Called getValue<T>() with incompatible type T.", exp.what());
		}
	}

private:
	Variant _value;
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
 * Class representing handler of pog parser.
 * It also serves as context storage for parsing.
 *
 * ParserDriver driver(ParserMode::Regular);
 *	for (input : inputs) {
 *		driver.setInput(input);
 * 	driver.parse();
 * 	result = driver.getParsedFile();
 * 	driver.reset();
 * }
 */
class ParserDriver
{
public:
	/// @name Constructors
	/// @{
	ParserDriver() = delete;
  	ParserDriver(ParserMode parserMode);
	explicit ParserDriver(const std::string& filePath, ParserMode parserMode = ParserMode::Regular);
	explicit ParserDriver(std::istream& input, ParserMode parserMode = ParserMode::Regular);
	void initialize();
	/// @}

	/// @name Destructor
	/// @{
	~ParserDriver() = default;
	/// @}

	/// @name Getter methods
	/// @{
	YaraFile& getParsedFile();
	const YaraFile& getParsedFile() const;
	/// @}

	/// @name Parsing methods
	/// @{
	bool parse();
	void reset(ParserMode parserMode = ParserMode::Regular);
	void setInput(std::istream& input);
	void setInput(const std::string& filePath);
	/// @}

	/// @name Detection methods
	/// @{
	bool isValid() const;
	/// @}

	/// @name Methods for handling comments
	/// @{
	void addComment(TokenIt comment);
	/// @}

protected:
	/// @name Methods for handling includes
	/// @{
	bool includeFile(const std::string& includePath);
	bool includeFileImpl(const std::string& includePath);
	bool isAlreadyIncluded(const std::string& includePath);
	std::istream* currentInputStream();
	bool includeEnd();
	/// @}

	/// @name Methods for handling rules
	/// @{
	bool ruleExists(const std::string& name) const;
	void addRule(Rule&& rule);
	void addRule(std::unique_ptr<Rule>&& rule);
	/// @}

	/// @name Methods for handling strings
	/// @{
	bool stringExists(const std::string& id) const;
	void setCurrentStrings(const std::shared_ptr<Rule::StringsTrie>& currentStrings);
	bool sectionStrings() const { return _sectionStrings; };
	void sectionStrings(bool new_value) { _sectionStrings = new_value; };
	/// @}

	/// @name Methods for parser maintainance
	/// @{
	void defineTokens();
	void defineGrammar();
	bool prepareParser();
	template <typename... Args> TokenIt emplace_back(Args&&... args);
	void enter_state(const std::string& state);
	void push_input_stream(std::istream& input) { _parser.push_input_stream(input); }
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
	const std::shared_ptr<TokenStream>& currentTokenStream() const { return _tokenStreams.top(); }
	void pushTokenStream(const std::shared_ptr<TokenStream>& ts) { _tokenStreams.push(ts); }
	std::size_t currentTokenStreamCount() const { return _tokenStreams.size(); }
	void popTokenStream() { _tokenStreams.pop(); }
	/// @}

	/// @name Methods for handling locations
	/// @{
	void pushLocation() { _locations.emplace(); }
	void popLocation() { _locations.pop(); }
	Location& currentLocation() { assert(!_locations.empty()); return _locations.top(); }
	std::size_t currentLocationCount() { return _locations.size(); }
	/// @}

private:
	std::string _strLiteral; ///< Currently processed string literal.
	std::string _indent; ///< Variable storing current indentation
	std::string _comment; ///< For incremental construction of parsed comments
	std::string _regexpClass; ///< Currently processed regular expression class.
	pog::Parser<Value> _parser; ///< used pog parser
	bool _sectionStrings = false; ///< flag used to determine if we parse section after 'strings:'

	ParserMode _mode; ///< Parser mode.

	std::stack<std::shared_ptr<TokenStream>> _tokenStreams; ///< _tokenStream contains all parsed tokens
	std::stack<Location> _locations; ///< the top location tracks position of currently parsed token within current input file
	std::vector<TokenIt> _comments; ///< Tokens of parsed comments

	std::vector<std::shared_ptr<std::istream>> _includedFiles; ///< Stack of included files
	std::vector<std::string> _includedFileNames; ///< Stack of included file names
	std::unordered_set<std::string> _includedFilesCache; ///< Cache of already included files
	std::istream* _optionalFirstInput; ///< Input file or stream

	bool _valid; ///< Validity
	std::string _filePath; ///< File path if parsing from file

	YaraFile _file; ///< Parsed file

	std::weak_ptr<Rule::StringsTrie> _currentStrings; ///< Context storage of current strings trie
	bool _stringLoop; ///< Context storage of for loop indicator
	std::unordered_map<std::string, std::shared_ptr<Symbol>> _localSymbols; ///< Context storage of local symbols

	std::uint64_t _startOfRule; ///< Holds the line number where the last parsed rule starts
	std::uint64_t _anonStringCounter; ///< Internal counter for generating pseudo identifiers of anonymous strings
};

} // namespace yaramod
