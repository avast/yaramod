/**
 * @file src/parser/parser_driver.cpp
 * @brief Implementation of class ParserDriver.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "yaramod/parser/parser_driver.h"
#include "yaramod/utils/filesystem.h"
#include "yaramod/types/expressions.h"
#include <pog/html_report.h>

namespace yaramod {

	void error_handle( const std::string& msg, std::size_t line, std::optional<std::size_t> byte = std::nullopt, std::optional<std::size_t> length = std::nullopt, bool except = true )
	{
		std::stringstream ss;
		ss << "Error at ";
		if( byte ) {
			ss << line << "." << byte.value() + 1;
			if( length )
				ss << "-" << byte.value() + length.value();
		}
		else
			ss << "line " << line;
		ss << ": " << msg;
		if( except )
			throw ParserError( ss.str() );
		else
			std::cerr << ss.str() << std::endl;
	}

	void error_handle( const std::string& msg )
	{
		throw ParserError(msg);
	}

/**
 * PogParser Constructor.
 *
 * @param driver ParserDriver.
 */
PogParser::PogParser(ParserDriver& driver)
	: _driver(driver)
{
	defineTokens();
	defineGrammar();
	_parser.set_start_symbol("rules");
	bool prepared = prepareParser();
	assert( prepared && "Parser initialization failed");
}

template<typename... Args>
TokenIt PogParser::emplace_back(Args&&... args)
{
	return _driver.currentStream()->emplace_back(args...);
}

void print(const std::string& symbol, const std::string_view& value) //TODO: remove
{
	//std::cerr << symbol << ": '" << std::string{value} << "'" << std::endl;
}
void print(const std::string& symbol, const std::string& value) //TODO: remove
{
	//std::cerr << symbol << ": '" << value << "'" << std::endl;
}

void PogParser::defineTokens()
{
	_parser.token("\n").action( [&](std::string_view str) -> Value {
		_indent.clear();
		_driver.moveLineLocation();
		return emplace_back(NEW_LINE, std::string{str});
	});
	_parser.token("[ \t\r]+").action( [&](std::string_view str) -> Value { // spaces, tabulators, carrige-returns
		_indent += std::string{str};
		return {};
	});

	_parser.token(R"(\.\.)").symbol("RANGE").action( [&](std::string_view str) -> Value { return emplace_back( RANGE, std::string{str} ); } );
	_parser.token(R"(\.)").symbol("DOT").action( [&](std::string_view str) -> Value { return emplace_back( DOT, std::string{str} ); } )
		.precedence(15, pog::Associativity::Left);
	_parser.token("<").symbol("LT").action( [&](std::string_view str) -> Value { return emplace_back( LT, std::string{str} ); } )
		.precedence(10, pog::Associativity::Left);
	_parser.token(">").symbol("GT").action( [&](std::string_view str) -> Value { return emplace_back( GT, std::string{str} ); } )
		.precedence(10, pog::Associativity::Left);
	_parser.token("<=").symbol("LE").action( [&](std::string_view str) -> Value { return emplace_back( LE, std::string{str} ); } )
		.precedence(10, pog::Associativity::Left);
	_parser.token(">=").symbol("GE").action( [&](std::string_view str) -> Value { return emplace_back( GE, std::string{str} ); } )
		.precedence(10, pog::Associativity::Left);
	_parser.token("==").symbol("EQ").action( [&](std::string_view str) -> Value { return emplace_back( EQ, std::string{str} ); } )
		.precedence(9, pog::Associativity::Left);
	_parser.token("!=").symbol("NEQ").action( [&](std::string_view str) -> Value { return emplace_back( NEQ, std::string{str} ); } )
		.precedence(9, pog::Associativity::Left);
	_parser.token("<<").symbol("SHIFT_LEFT").action( [&](std::string_view str) -> Value { return emplace_back( SHIFT_LEFT, std::string{str} ); } )
		.precedence(11, pog::Associativity::Left);
	_parser.token(">>").symbol("SHIFT_RIGHT").action( [&](std::string_view str) -> Value { return emplace_back( SHIFT_RIGHT, std::string{str} ); } )
		.precedence(11, pog::Associativity::Left);
	_parser.token(R"(-)").symbol("MINUS").action( [&](std::string_view str) -> Value { return emplace_back(MINUS, std::string{str}); } )
		.precedence(12, pog::Associativity::Left);
	_parser.token(R"(\+)").symbol("PLUS").action( [&](std::string_view str) -> Value { return emplace_back(PLUS, std::string{str}); } )
		.precedence(12, pog::Associativity::Left);
	_parser.token(R"(\*)").symbol("MULTIPLY").action( [&](std::string_view str) -> Value { return emplace_back(MULTIPLY, std::string{str}); } )
		.precedence(13, pog::Associativity::Left);
	_parser.token(R"(\\)").symbol("DIVIDE").action( [&](std::string_view str) -> Value { return emplace_back(DIVIDE, std::string{str}); } )
		.precedence(13, pog::Associativity::Left);
	_parser.token(R"(\%)").symbol("MODULO").action( [&](std::string_view str) -> Value { return emplace_back(MODULO, std::string{str}); } )
		.precedence(13, pog::Associativity::Left);
	_parser.token(R"(\^)").symbol("BITWISE_XOR").action( [&](std::string_view str) -> Value { return emplace_back(BITWISE_XOR, std::string{str}); } )
		.precedence(7, pog::Associativity::Left);
	_parser.token(R"(\&)").symbol("BITWISE_AND").action( [&](std::string_view str) -> Value { return emplace_back(BITWISE_AND, std::string{str}); } )
		.precedence(8, pog::Associativity::Left);
	_parser.token(R"(\|)").symbol("BITWISE_OR").action( [&](std::string_view str) -> Value { return emplace_back(BITWISE_OR, std::string{str}); } )
		.precedence(6, pog::Associativity::Left);
	_parser.token(R"(\~)").symbol("BITWISE_NOT").action( [&](std::string_view str) -> Value { return emplace_back(BITWISE_NOT, std::string{str}); } )
		.precedence(14, pog::Associativity::Right);
	_parser.token("\\(").symbol("LP").action( [&](std::string_view str) -> Value { return emplace_back(LP, std::string{str}); } );
	_parser.token("\\)").symbol("RP").action( [&](std::string_view str) -> Value { return emplace_back(RP, std::string{str}); } )
		.precedence(1, pog::Associativity::Left);
	_parser.token("\\{").symbol("LCB").action( [&](std::string_view str) -> Value {
		if(sectionStrings())
			enter_state("@hexstr");
		return emplace_back(LCB, std::string{str});
	});
	_parser.token("\\}").symbol("RCB").action( [&](std::string_view str) -> Value { return emplace_back(RCB, std::string{str}); } );
	_parser.token("\\[").symbol("LSQB").action( [&](std::string_view str) -> Value { return emplace_back( LSQB, std::string{str} ); } );
	_parser.token("\\]").symbol("RSQB").action( [&](std::string_view str) -> Value { return emplace_back( RSQB, std::string{str} ); } );
	_parser.token("=").symbol("ASSIGN").action( [&](std::string_view str) -> Value { return emplace_back( ASSIGN, std::string{str} ); } );
	_parser.token(":").symbol("COLON").action( [&](std::string_view str) -> Value { return emplace_back( COLON, std::string{str} ); } );
	_parser.token(",").symbol("COMMA").action( [&](std::string_view str) -> Value { return emplace_back( COMMA, std::string{str} ); } )
		.precedence(1, pog::Associativity::Left);
	_parser.token("/").states("@default").symbol("SLASH").action( [&](std::string_view str) -> Value {
		enter_state("@regexp");
		return std::string{str};
	});
	_parser.token("global").symbol("GLOBAL").action( [&](std::string_view str) -> Value { return emplace_back(GLOBAL, std::string{str}); } );
	_parser.token("private").symbol("PRIVATE").action( [&](std::string_view str) -> Value { return emplace_back(PRIVATE, std::string{str}); } );
	_parser.token("rule").symbol("RULE").action( [&](std::string_view str) -> Value { _driver.markStartOfRule(); return emplace_back( RULE, std::string{str} ); } );
	_parser.token("meta").symbol("META").action( [&](std::string_view str) -> Value { return emplace_back( META, std::string{str} ); } );
	_parser.token("strings").symbol("STRINGS").action( [&](std::string_view str) -> Value { sectionStrings(true); return emplace_back( STRINGS, std::string{str} ); } );
	_parser.token("condition").symbol("CONDITION").action( [&](std::string_view str) -> Value { sectionStrings(false); return emplace_back( CONDITION, std::string{str} ); } );
	_parser.token("ascii").symbol("ASCII").action( [&](std::string_view str) -> Value { return emplace_back( ASCII, std::string{str} ); } );
	_parser.token("nocase").symbol("NOCASE").action( [&](std::string_view str) -> Value { return emplace_back( NOCASE, std::string{str} ); } );
	_parser.token("wide").symbol("WIDE").action( [&](std::string_view str) -> Value { return emplace_back( WIDE, std::string{str} ); } );
	_parser.token("fullword").symbol("FULLWORD").action( [&](std::string_view str) -> Value { return emplace_back( FULLWORD, std::string{str} ); } );
	_parser.token("xor").symbol("XOR").action( [&](std::string_view str) -> Value { return emplace_back( XOR, std::string{str} ); } );
	_parser.token("true").symbol("BOOL_TRUE").action( [&](std::string_view) -> Value { return emplace_back( BOOL_TRUE, true ); } );
	_parser.token("false").symbol("BOOL_FALSE").action( [&](std::string_view) -> Value { return emplace_back( BOOL_FALSE, false ); } );
	_parser.token("import").symbol("IMPORT_KEYWORD").action( [&](std::string_view str) -> Value { return emplace_back( IMPORT_KEYWORD, std::string{str} ); } );
	_parser.token("not").symbol("NOT").action( [&](std::string_view str) -> Value { return emplace_back( NOT, std::string{str} ); } )
		.precedence(14, pog::Associativity::Right);
	_parser.token("and").symbol("AND").action( [&](std::string_view str) -> Value { return emplace_back( AND, std::string{str} ); } )
		.precedence(5, pog::Associativity::Left);
	_parser.token("or").symbol("OR").action( [&](std::string_view str) -> Value { return emplace_back( OR, std::string{str} ); } )
		.precedence(4, pog::Associativity::Left);
	_parser.token("all").symbol("ALL").action( [&](std::string_view str) -> Value { return emplace_back( ALL, std::string{str} ); } );
	_parser.token("any").symbol("ANY").action( [&](std::string_view str) -> Value { return emplace_back( ANY, std::string{str} ); } );
	_parser.token("of").symbol("OF").action( [&](std::string_view str) -> Value { return emplace_back( OF, std::string{str} ); } );
	_parser.token("them").symbol("THEM").action( [&](std::string_view str) -> Value { return emplace_back( THEM, std::string{str} ); } );
	_parser.token("for").symbol("FOR").action( [&](std::string_view str) -> Value { return emplace_back( FOR, std::string{str} ); } );
	_parser.token("entrypoint").symbol("ENTRYPOINT").action( [&](std::string_view str) -> Value { return emplace_back( ENTRYPOINT, std::string{str} ); } );
	_parser.token("at").symbol("AT").action( [&](std::string_view str) -> Value { return emplace_back( OP_AT, std::string{str} ); } );
	_parser.token("in").symbol("IN").action( [&](std::string_view str) -> Value { return emplace_back( OP_IN, std::string{str} ); } );
	_parser.token("filesize").symbol("FILESIZE").action( [&](std::string_view str) -> Value { return emplace_back( FILESIZE, std::string{str} ); } );
	_parser.token("contains").symbol("CONTAINS").action( [&](std::string_view str) -> Value { return emplace_back( CONTAINS, std::string{str} ); } );
	_parser.token("matches").symbol("MATCHES").action( [&](std::string_view str) -> Value { return emplace_back( MATCHES, std::string{str} ); } );
	_parser.token("include").symbol("INCLUDE_DIRECTIVE").action( [&](std::string_view str) -> Value { return emplace_back(INCLUDE_DIRECTIVE, std::string{str}); } );

	_parser.token(R"(0x[0-9a-fA-F]+)").symbol("INTEGER").action( [&](std::string_view str) -> Value {
		return emplace_back(INTEGER, std::stol(std::string{str}.substr(2), 0, 16), std::make_optional(std::string{str}) );
	});
	_parser.token(R"([0-9]+KB)").symbol("INTEGER").action( [&](std::string_view str) -> Value {
		return emplace_back(INTEGER, 1000 * std::stol(std::string{str}), std::make_optional(std::string{str}));
	});
	_parser.token(R"([0-9]+MB)").symbol("INTEGER").action( [&](std::string_view str) -> Value {
		return emplace_back(INTEGER, 1000000 * std::stol(std::string{str}), std::make_optional(std::string{str}));
	});
	_parser.token(R"([0-9]+)").symbol("INTEGER").action( [&](std::string_view str) -> Value {
		return emplace_back(INTEGER, std::stol(std::string{str}), std::make_optional(std::string{str}));
	});

	_parser.token(R"(\/\/[^\n]*)").states("@default").action( [&](std::string_view str) -> Value {
		auto it = emplace_back(ONELINE_COMMENT, std::string{str}, _indent);
		_driver.addComment(it);
		return {};
	});
	// @multiline_comment
	// Comment tokens are not delegated with return Value but stored in _comment
	_parser.token(R"(/\*)").states("@default").enter_state("@multiline_comment").action( [&](std::string_view str) -> Value {
		_comment.append(std::string{str});
		return {};
	});
	_parser.token(R"(\*/)").states("@multiline_comment").enter_state("@default").action( [&](std::string_view str) -> Value {
		_comment.append(std::string{str});
		auto it = emplace_back(COMMENT, _comment, _indent);
		_driver.addComment(it);
		_indent.clear();
		_comment.clear();
		return {};
	});
	_parser.token(R"(\n)").states("@multiline_comment").action( [&](std::string_view str) -> Value {
		_driver.moveLineLocation();
		_comment.append(std::string{str});
		return {};
	});
	_parser.token(R"(.)").states("@multiline_comment").action( [&](std::string_view str) -> Value {
		_comment.append(std::string{str});
		return {};
	});
	// @multiline_comment end

	// @str
	// @str tokens are not delegated with return Value but stored in _strLiteral
	_parser.token(R"(\")").states("@default").enter_state("@str").action( [&](std::string_view) -> Value {
		_strLiteral.clear();
		return {};
	});
	_parser.token(R"(\\t)").states("@str").action( [&](std::string_view) -> Value {
		_strLiteral += '\t';
		return {};
	});
	_parser.token(R"(\\n)").states("@str").action( [&](std::string_view) -> Value {
		_strLiteral += '\n';
		_driver.moveLineLocation();
		return {};
	});
	_parser.token(R"(\\x[0-9a-fA-F]{2})").states("@str").action( [&](std::string_view str) -> Value {
		std::uint64_t num = 0;
		strToNum(std::string{str}.substr(2), num, std::hex);
		_strLiteral += static_cast<char>(num);
		return {};
	});
	_parser.token(R"(\\\")").states("@str").action([&](std::string_view) -> Value { _strLiteral += '\"'; return {}; } );
	_parser.token(R"(\\\\)").states("@str").action([&](std::string_view) -> Value { _strLiteral += '\\'; return {}; } );
	_parser.token(R"(\\\.)").states("@str").action([&](std::string_view str) -> Value { throw ParserError(std::string("Error at <TODO>: Unknown escape sequence \'" + std::string{str} + "\'")); return {}; });
	_parser.token(R"(([^\\"])+)").states("@str").action([&](std::string_view str) -> Value { _strLiteral += std::string{str}; return {}; });
	_parser.token(R"(\")").states("@str").symbol("STRING_LITERAL").enter_state("@default").action([&](std::string_view) -> Value {
		return emplace_back(STRING_LITERAL, _strLiteral);
	});
	// @str end

	_parser.token("u?int(8|16|32)(be)?").symbol("INTEGER_FUNCTION").action( [&](std::string_view str) -> Value { return emplace_back(INTEGER_FUNCTION, std::string{str}); } );
	_parser.token(R"(\$[0-9a-zA-Z_]*)").symbol("STRING_ID").action([&](std::string_view str) -> Value { return emplace_back(STRING_ID, std::string{str}); });

	_parser.token(R"(\$[0-9a-zA-Z_]*\*)").symbol("STRING_ID_WILDCARD").action([&](std::string_view str) -> Value { return emplace_back(STRING_ID_WILDCARD, std::string{str}); });
	_parser.token(R"(\#[0-9a-zA-Z_]*)").symbol("STRING_COUNT").action([&](std::string_view str) -> Value { return emplace_back(STRING_COUNT, std::string{str}); });
	_parser.token(R"(\@[0-9a-zA-Z_]*)").symbol("STRING_OFFSET").action([&](std::string_view str) -> Value { return emplace_back(STRING_OFFSET, std::string{str}); });
	_parser.token(R"(\![0-9a-zA-Z_]*)").symbol("STRING_LENGTH").action([&](std::string_view str) -> Value { return emplace_back(STRING_LENGTH, std::string{str}); });
	_parser.token("[a-zA-Z_][0-9a-zA-Z_]*").symbol("ID").action([&](std::string_view str) -> Value { return emplace_back(ID, std::string{str}); });

	_parser.token(R"([0-9]+\.[0-9]+)").symbol("DOUBLE").action([&](std::string_view str) -> Value { return emplace_back(DOUBLE, std::stod(std::string(str))); });

	// @hexstr
	_parser.token(R"(\|)").states("@hexstr").symbol("HEX_OR").action([&](std::string_view str) -> Value { return emplace_back(HEX_ALT, std::string{str}); });
	_parser.token(R"(\()").states("@hexstr").symbol("LP").action([&](std::string_view str) -> Value { return emplace_back(LP, std::string{str}); });
	_parser.token(R"(\))").states("@hexstr").symbol("RP").action([&](std::string_view str) -> Value { return emplace_back(RP, std::string{str}); });
	_parser.token(R"(\?)").states("@hexstr").symbol("HEX_WILDCARD").action([&](std::string_view str) -> Value { return emplace_back(HEX_WILDCARD, std::string{str}); });
	_parser.token(R"(\})").states("@hexstr").enter_state("@default").symbol("RCB").action([&](std::string_view) -> Value { return emplace_back(RCB, "}"); });
	_parser.token("[0-9a-fA-F]").states("@hexstr").symbol("HEX_NIBBLE").action([&](std::string_view str) -> Value {
		uint8_t digit = ('A' <= std::toupper(str[0]) && std::toupper(str[0]) <= 'F') ? std::toupper(str[0]) - 'A' + 10 : str[0] - '0';
		return emplace_back(HEX_NIBBLE, digit, std::string{str});
	});
	_parser.token(R"(\[)").states("@hexstr").enter_state("@hexstr_jump").symbol("LSQB").action([&](std::string_view str) -> Value { return emplace_back(HEX_JUMP_LEFT_BRACKET, std::string{str}); });
	_parser.token("[0-9]*").states("@hexstr_jump").symbol("HEX_INTEGER").action([&](std::string_view str) -> Value {
		std::string numStr = std::string{str};
		std::uint64_t num = 0;
		strToNum(numStr, num, std::dec);
		return emplace_back(INTEGER, num, numStr);
	});
	_parser.token(R"(\-)").states("@hexstr_jump").symbol("DASH").action([&](std::string_view str) -> Value { return emplace_back(DASH, std::string{str}); });
	_parser.token(R"(\])").states("@hexstr_jump").symbol("RSQB").enter_state("@hexstr").action([&](std::string_view str) -> Value { return emplace_back(HEX_JUMP_RIGHT_BRACKET, std::string{str}); });

	// tokens are not delegated with return Value but created in grammar rules actions
	_parser.token(R"(//[^\n]*)").states("@hexstr_jump").action([](std::string_view str) -> Value { return std::string{str}; });
	_parser.token(R"(///*)").states("@hexstr").enter_state("@hexstr_multiline_comment");
	_parser.token(R"(.)").states("@hexstr_multiline_comment");
	_parser.token(R"(/*//)").states("@hexstr_multiline_comment").enter_state("@hexstr");
	_parser.token(R"({[ \v\r\t]}*)").states("@hexstr", "@hexstr_jump").action([&](std::string_view) -> Value { return {}; });;
	_parser.token(R"([\n])").states("@hexstr", "@hexstr_jump").action([&](std::string_view) -> Value {
		return emplace_back(NEW_LINE, "\n");
	});
	_parser.token(R"(\s)").states("@hexstr", "@hexstr_jump");
	// @hexstr end

	// @regexp
	// @regexp tokens are delegated as strings and then emplaced to TokenStream in grammar rules actions
	_parser.token(R"(/i?s?)").states("@regexp").enter_state("@default").symbol("SLASH").action([&](std::string_view str) -> Value {
		return std::string{str};
	});
	_parser.token(R"(\()").states("@regexp").symbol("LP").action([&](std::string_view str) -> Value { return std::string{str}; });
	_parser.token(R"(\))").states("@regexp").symbol("RP").action([&](std::string_view str) -> Value { return std::string{str}; });
	_parser.token(R"(\|)").states("@regexp").symbol("REGEXP_OR").action([&](std::string_view str) -> Value { return std::string{str}; });
	_parser.token(R"(\*)").states("@regexp").symbol("REGEXP_ITER").action([&](std::string_view str) -> Value { return std::string{str}; });
	_parser.token(R"(\+)").states("@regexp").symbol("REGEXP_PITER").action([&](std::string_view str) -> Value { return std::string{str}; });
	_parser.token(R"(\?)").states("@regexp").symbol("REGEXP_OPTIONAL").action([&](std::string_view str) -> Value { return std::string{str}; });
	_parser.token(R"(\^)").states("@regexp").symbol("REGEXP_START_OF_LINE").action([&](std::string_view str) -> Value { return std::string{str}; });
	_parser.token(R"(\$)").states("@regexp").symbol("REGEXP_END_OF_LINE").action([&](std::string_view str) -> Value { return std::string{str}; });
	_parser.token(R"(\.)").states("@regexp").symbol("REGEXP_ANY_CHAR").action([&](std::string_view str) -> Value { return std::string{str}; });
	_parser.token(R"(\{[0-9]*,[0-9]*\})").states("@regexp").symbol("REGEXP_RANGE").action( [&](std::string_view str) -> Value {
		std::string rangeStr = std::string{str};
		std::string lowStr = rangeStr.substr(1, rangeStr.find(',') - 1);
		std::string highStr = rangeStr.substr(rangeStr.find(',') + 1);
		highStr.pop_back(); // Remove '}' at the end

		std::uint64_t lowNum = 0;
		std::optional<std::uint64_t> low;
		if (strToNum(lowStr, lowNum, std::dec))
			low = lowNum;

		std::uint64_t highNum = 0;
		std::optional<std::uint64_t> high;
		if (strToNum(highStr, highNum, std::dec))
			high = highNum;

		return std::make_pair(low, high);
	});
	_parser.token(R"({[0-9]+})").states("@regexp").symbol("REGEXP_RANGE").action( [&](std::string_view str) -> Value {
		std::string numStr = std::string(str.substr(1, str.size()-2));

		std::optional<std::uint64_t> range;
		std::uint64_t num = 0;
		if (strToNum(numStr, num, std::dec))
			range = num;

		return std::make_pair(range, range);
	});
	_parser.token(R"([^\\\[\(\)\|\$\.\^\+\+*\?])").states("@regexp").symbol("REGEXP_CHAR").action( [&](std::string_view str) -> Value {
		return std::string(1, str[0]);
	});
	_parser.token(R"(\\w)").states("@regexp").symbol("REGEXP_WORD_CHAR").action( [&](std::string_view) -> Value { return {};} );
	_parser.token(R"(\\W)").states("@regexp").symbol("REGEXP_NON_WORD_CHAR").action( [&](std::string_view) -> Value { return {};} );
	_parser.token(R"(\\s)").states("@regexp").symbol("REGEXP_SPACE").action( [&](std::string_view) -> Value { return {};} );
	_parser.token(R"(\\S)").states("@regexp").symbol("REGEXP_NON_SPACE").action( [&](std::string_view) -> Value { return {};} );
	_parser.token(R"(\\d)").states("@regexp").symbol("REGEXP_DIGIT").action( [&](std::string_view) -> Value { return {};} );
	_parser.token(R"(\\D)").states("@regexp").symbol("REGEXP_NON_DIGIT").action( [&](std::string_view) -> Value { return {};} );
	_parser.token(R"(\\b)").states("@regexp").symbol("REGEXP_WORD_BOUNDARY").action( [&](std::string_view) -> Value { return {};} );
	_parser.token(R"(\\B)").states("@regexp").symbol("REGEXP_NON_WORD_BOUNDARY").action( [&](std::string_view) -> Value { return {};} );
	_parser.token(R"(\\.)").states("@regexp").symbol("REGEXP_CHAR").action( [&](std::string_view str) -> Value {
		return std::string{str};
	});
	_parser.token(R"(\[\^\])").states("@regexp").enter_state("@regexp_class").action([&](std::string_view) -> Value {
		_regexpClass = "^]";
		return {};
	});
	_parser.token(R"(\[\])").states("@regexp").enter_state("@regexp_class").action([&](std::string_view) -> Value {
		_regexpClass = "]";
		return {};
	});
	_parser.token(R"(\[\^)").states("@regexp").enter_state("@regexp_class").action([&](std::string_view) -> Value {
		_regexpClass = "^";
		return {};
}	);
	_parser.token(R"(\[)").states("@regexp").enter_state("@regexp_class").action([&](std::string_view) -> Value {
		_regexpClass.clear();
		return {};
}	);
	_parser.token(R"(\])").states("@regexp_class").symbol("REGEXP_CLASS").enter_state("@regexp").action([&](std::string_view) -> Value {
		return _regexpClass;
	});
	_parser.token(R"(\\w)").states("@regexp_class").symbol("REGEXP_WORD_CHAR").action( [&](std::string_view) -> Value { _regexpClass += "\\w"; return {};} );
	_parser.token(R"(\\W)").states("@regexp_class").symbol("REGEXP_NON_WORD_CHAR").action( [&](std::string_view) -> Value { _regexpClass += "\\W"; return {};} );
	_parser.token(R"(\\s)").states("@regexp_class").symbol("REGEXP_SPACE").action( [&](std::string_view) -> Value { _regexpClass += "\\s"; return {};} );
	_parser.token(R"(\\S)").states("@regexp_class").symbol("REGEXP_NON_SPACE").action( [&](std::string_view) -> Value { _regexpClass += "\\S"; return {};} );
	_parser.token(R"(\\d)").states("@regexp_class").symbol("REGEXP_DIGIT").action( [&](std::string_view) -> Value { _regexpClass += "\\d"; return {};} );
	_parser.token(R"(\\D)").states("@regexp_class").symbol("REGEXP_NON_DIGIT").action( [&](std::string_view) -> Value { _regexpClass += "\\D"; return {};} );
	_parser.token(R"(\\b)").states("@regexp_class").symbol("REGEXP_WORD_BOUNDARY").action( [&](std::string_view) -> Value { _regexpClass += "\\b"; return {};} );
	_parser.token(R"(\\B)").states("@regexp_class").symbol("REGEXP_NON_WORD_BOUNDARY").action( [&](std::string_view) -> Value { _regexpClass += "\\B"; return {};} );
	_parser.token(R"([^]])").states("@regexp_class").action( [&](std::string_view str) -> Value { _regexpClass += std::string{str}[0]; return {}; });
	// @regexp end

	_parser.end_token().action([](std::string_view str) -> Value { return {}; });
}

void PogParser::defineGrammar()
{
	_parser.rule("rules")
		.production("rules", "rule")
		.production("rules", "import")
		.production()
		;
	_parser.rule("import") // {}
		.production("IMPORT_KEYWORD", "STRING_LITERAL", [&](auto&& args) -> Value {
			TokenIt import = args[1].getTokenIt();
			import->setType(IMPORT_MODULE);
			if(!_driver._file.addImport(import))
				error_handle("Unrecognized module '" + import->getString() + "' imported");
			return {};
		});

	_parser.rule("rule") // {}
		.production(
			"rule_mod", "RULE", "rule_name", [&](auto&& args) -> Value {
				if(_driver.ruleExists(args[2].getTokenIt()->getString()))
					error_handle("Rule already exists");
				return {};
			},
			"tags", "rule_begin", "metas", "strings", "condition", "rule_end", [&](auto&& args) -> Value {
				TokenIt name = args[2].getTokenIt();
				std::optional<TokenIt> mod = std::move(args[0].getOptionalTokenIt());
				std::vector<Meta> metas = std::move(args[6].getMetas());
				std::shared_ptr<Rule::StringsTrie> strings = std::move(args[7].getStringsTrie());
				Expression::Ptr condition = std::move(args[8].getExpression());
				const std::vector<TokenIt> tags = std::move(args[4].getMultipleTokenIt());

				_driver.addRule(Rule(_driver.currentStream(), name, std::move(mod), std::move(metas), std::move(strings), std::move(condition), std::move(tags)));
				return {};
			});

	_parser.rule("rule_mod") // optional<TokenIt>
		.production("GLOBAL", [&](auto&& args) -> Value { return std::make_optional(args[0].getTokenIt()); })
		.production("PRIVATE", [&](auto&& args) -> Value { return std::make_optional(args[0].getTokenIt()); })
		.production([&](auto&&) -> Value { return Value(std::nullopt); })
		;
	_parser.rule("rule_name") // TokenIt
		.production("ID", [&](auto&& args) -> Value {
			args[0].getTokenIt()->setType(RULE_NAME);
			return args[0];
		});
	_parser.rule("tags") // vector<TokenIt>
		.production("COLON", "tag_list", [](auto&& args) -> Value {
			return std::move(args[1]);
		})
		.production([](auto&&) -> Value {
			return std::vector<TokenIt>();
		})
		;
	_parser.rule("tag_list") // vector<TokenIt>
		.production("tag_list", "ID", [&](auto&& args) -> Value {
			std::vector<TokenIt> tags = std::move(args[0].getMultipleTokenIt());
			TokenIt tag = args[1].getTokenIt();
			tag->setType(TAG);
			tags.emplace_back(std::move(tag));
			return Value(std::move(tags));
		})
		.production("ID", [&](auto&& args) -> Value {
			std::vector<TokenIt> tags;
			TokenIt tag = args[0].getTokenIt();
			tag->setType(TAG);
			tags.emplace_back(std::move(tag));
			return Value(std::move(tags));
		})
		;
	_parser.rule("rule_begin") // TokenIt
		.production("LCB", [&](auto&& args) -> Value {
			args[0].getTokenIt()->setType(RULE_BEGIN);
			return args[0];
		})
		;
	_parser.rule("rule_end") // TokenIt
		.production("RCB", [&](auto&& args) -> Value {
			args[0].getTokenIt()->setType(RULE_END);
			return args[0];
		})
		;
	_parser.rule("metas") // vector<Meta>
		.production("META", "COLON", "metas_body", [](auto&& args) -> Value { return std::move(args[2]); })
		.production([](auto&&) -> Value { return std::vector<yaramod::Meta>(); })
		;

	_parser.rule("metas_body") // vector<Meta>
		.production("metas_body", "ID", "ASSIGN", "literal", [&](auto&& args) -> Value {
			std::vector<Meta> body = std::move(args[0].getMetas());
			TokenIt key = args[1].getTokenIt();
			key->setType(META_KEY);
			TokenIt val = args[3].getTokenIt();
			val->setType(META_VALUE);
			body.emplace_back(key, val);
			return Value(std::move(body));
		})
		.production([](auto&&) -> Value { return std::vector<yaramod::Meta>(); })
		;

	_parser.rule("literal") //TokenIt
		.production("STRING_LITERAL", [](auto&& args) -> Value { return std::move(args[0]); })
		.production("INTEGER", [](auto&& args) -> Value { return std::move(args[0]); })
		.production("boolean", [](auto&& args) -> Value { return std::move(args[0]); })
		;

	_parser.rule("boolean") // TokenIt
		.production("BOOL_TRUE", [](auto&& args) -> Value { return std::move(args[0]); })
		.production("BOOL_FALSE", [](auto&& args) -> Value { return std::move(args[0]); })
		;

	_parser.rule("strings") // shared_ptr<StringsTrie>
		.production("STRINGS", "COLON", "strings_body", [](auto&& args) -> Value { return std::move(args[2]); })
		.production([&](auto&&) -> Value {
			auto strings = std::make_shared<Rule::StringsTrie>();
			_driver.setCurrentStrings(strings);
			return std::move(strings);
		})
		;
	_parser.rule("strings_body") // shared_ptr<StringsTrie>
		.production(
			"strings_body", "string_id", "ASSIGN", [&](auto&&) -> Value {
				return {};
			},
			"string", [&](auto&& args) -> Value {
				const std::string& id = args[1].getTokenIt()->getPureText();
				const std::string& trieId = _driver.isAnonymousStringId(id) ? _driver.generateAnonymousStringPseudoId() : id;
				auto string = std::move(args[4].getYaramodString());
				string->setIdentifier(args[1].getTokenIt(), args[2].getTokenIt());
				auto strings = std::move(args[0].getStringsTrie());
				if(!strings->insert(trieId, std::move(string)))
				{
					error_handle("Redefinition of string '" + trieId + "'");
				}
				return std::move(strings);
			}
		)
		.production([&](auto&&) -> Value {
			auto strings = std::make_shared<Rule::StringsTrie>();
			_driver.setCurrentStrings(strings);
			return std::move(strings);
		})
		;

	_parser.rule("string_id") // TokenIt
		.production("STRING_ID", [&](auto&& args) -> Value { return std::move(args[0]); });
	_parser.rule("string")
		.production("STRING_LITERAL", "string_mods", [&](auto&& args) -> Value {
			auto string = std::make_shared<PlainString>(_driver.currentStream(), std::move(args[0].getTokenIt()));
			std::pair<std::uint32_t, std::vector<TokenIt>> mods = std::move(args[1].getStringMods());
			string->setModifiers(mods.first, std::move(mods.second));
			return Value(std::move(string));
		})
		.production("LCB", [&](auto&& args) -> Value {
				args[0].getTokenIt()->setType(HEX_START_BRACKET);
				return {};
			},
		 	"hex_string", "RCB", [&](auto&& args) -> Value {
				args[3].getTokenIt()->setType(HEX_END_BRACKET);
			 	return Value(std::make_shared<HexString>(_driver.currentStream(), std::move(args[2].getMultipleHexUnits())));
			}
		)
		.production("regexp", "string_mods", [&](auto&& args) -> Value {
			auto regexp_string = std::move(args[0].getYaramodString());
			std::pair<std::uint32_t, std::vector<TokenIt>> mods = std::move(args[1].getStringMods());
			std::static_pointer_cast<Regexp>(regexp_string)->setModifiers(mods.first, std::move(mods.second));
			return Value(std::move(regexp_string));
		})
		;

	_parser.rule("string_mods") // pair<uint32_t, vector<TokenIt>>
		.production("string_mods", "ASCII", [](auto&& args) -> Value {
			std::pair<std::uint32_t, std::vector<TokenIt>> mods = std::move(args[0].getStringMods());
			mods.first = mods.first | String::Modifiers::Ascii;
			mods.second.push_back(args[1].getTokenIt());
			return Value(std::move(mods));
		})
		.production("string_mods", "WIDE", [](auto&& args) -> Value {
			std::pair<std::uint32_t, std::vector<TokenIt>> mods = std::move(args[0].getStringMods());
			mods.first = mods.first | String::Modifiers::Wide;
			mods.second.push_back(args[1].getTokenIt());
			return Value(std::move(mods));
		})
		.production("string_mods", "NOCASE", [](auto&& args) -> Value {
			std::pair<std::uint32_t, std::vector<TokenIt>> mods = std::move(args[0].getStringMods());
			mods.first = mods.first | String::Modifiers::Nocase;
			mods.second.push_back(args[1].getTokenIt());
			return Value(std::move(mods));
		})
		.production("string_mods", "FULLWORD", [](auto&& args) -> Value {
			std::pair<std::uint32_t, std::vector<TokenIt>> mods = std::move(args[0].getStringMods());
			mods.first = mods.first | String::Modifiers::Fullword;
			mods.second.push_back(args[1].getTokenIt());
			return Value(std::move(mods));
		})
		.production("string_mods", "XOR", [](auto&& args) -> Value {
			std::pair<std::uint32_t, std::vector<TokenIt>> mods = std::move(args[0].getStringMods());
			mods.first = mods.first | String::Modifiers::Xor;
			mods.second.push_back(args[1].getTokenIt());
			return Value(std::move(mods));
		})
		.production([](auto&&) -> Value {
			return Value(std::make_pair(String::Modifiers::None, std::move(std::vector<TokenIt>())));
		})
		;

	_parser.rule("hex_string") // vector<shared_ptr<HexStringUnit>>
		.production("hex_string_edge", [](auto&& args) -> Value {
			return std::move(args[0]);
		})
		.production("hex_string_edge", "hex_string_body", "hex_string_edge", [](auto&& args) -> Value {
			std::vector<std::shared_ptr<HexStringUnit>> output = std::move(args[0].getMultipleHexUnits());
			std::vector<std::shared_ptr<HexStringUnit>> body = std::move(args[1].getMultipleHexUnits());
			std::vector<std::shared_ptr<HexStringUnit>> edge = std::move(args[2].getMultipleHexUnits());
			output.reserve(output.size() + body.size() + edge.size());
			std::move(body.begin(), body.end(), std::back_inserter(output));
			std::move(edge.begin(), edge.end(), std::back_inserter(output));
			return output;
		})
		;

	_parser.rule("hex_string_edge") // vector<shared_ptr<HexStringUnit>>
		.production("hex_byte", [](auto&& args) -> Value {
			return std::move(args[0]);
		})
		.production("hex_or", [](auto&& args) -> Value {
			std::vector<std::shared_ptr<yaramod::HexStringUnit>> units;
			units.push_back(std::move(args[0].getHexUnit()));
			return std::move(units);
		})
		;
	_parser.rule("hex_byte") // vector<shared_ptr<HexStringUnit>>
		.production("HEX_NIBBLE", "HEX_NIBBLE", [](auto&& args) -> Value {
			std::vector<std::shared_ptr<HexStringUnit>> output;
			auto first = std::make_shared<HexStringNibble>(args[0].getTokenIt());
			auto second = std::make_shared<HexStringNibble>(args[1].getTokenIt());
			output.reserve(2);
			output.push_back(std::move(first));
			output.push_back(std::move(second));
			return std::move(output);
		})
		.production("HEX_NIBBLE", "HEX_WILDCARD", [](auto&& args) -> Value {
			std::vector<std::shared_ptr<HexStringUnit>> output;
			auto first = std::make_shared<HexStringNibble>(args[0].getTokenIt());
			args[1].getTokenIt()->setType(HEX_WILDCARD_HIGH);
			auto second = std::make_shared<HexStringWildcard>(args[1].getTokenIt());
			output.reserve(2);
			output.push_back(std::move(first));
			output.push_back(std::move(second));
			return std::move(output);
		})
		.production("HEX_WILDCARD", "HEX_NIBBLE", [](auto&& args) -> Value {
			std::vector<std::shared_ptr<HexStringUnit>> output;
			args[0].getTokenIt()->setType(HEX_WILDCARD_LOW);
			auto first = std::make_shared<HexStringWildcard>(args[0].getTokenIt());
			auto second = std::make_shared<HexStringNibble>(args[1].getTokenIt());
			output.reserve(2);
			output.push_back(std::move(first));
			output.push_back(std::move(second));
			return std::move(output);
		})
		.production("HEX_WILDCARD", "HEX_WILDCARD", [](auto&& args) -> Value {
			std::vector<std::shared_ptr<HexStringUnit>> output;
			args[0].getTokenIt()->setType(HEX_WILDCARD_LOW);
			auto first = std::make_shared<HexStringWildcard>(args[0].getTokenIt());
			args[1].getTokenIt()->setType(HEX_WILDCARD_HIGH);
			auto second = std::make_shared<HexStringWildcard>(args[1].getTokenIt());
			output.reserve(2);
			output.push_back(std::move(first));
			output.push_back(std::move(second));
			return std::move(output);
		})
		;
	_parser.rule("hex_string_body") // vector<shared_ptr<HexStringUnit>>
		.production("hex_string_body", "hex_byte", [](auto&& args) -> Value {
			std::vector<std::shared_ptr<HexStringUnit>> body = std::move(args[0].getMultipleHexUnits());
			std::vector<std::shared_ptr<HexStringUnit>> byte = std::move(args[1].getMultipleHexUnits());
			std::move(byte.begin(), byte.end(), std::back_inserter(body));
			return Value(std::move(body));
		})
		.production("hex_string_body", "hex_or", [](auto&& args) -> Value {
			std::vector<std::shared_ptr<HexStringUnit>> body = std::move(args[0].getMultipleHexUnits());
			body.push_back(std::move(args[1].getHexUnit()));
			return std::move(body);
		})
		.production("hex_string_body", "hex_jump", [](auto&& args) -> Value {
			std::vector<std::shared_ptr<HexStringUnit>> body = std::move(args[0].getMultipleHexUnits());
			body.push_back(std::move(args[1].getHexUnit()));
			return std::move(body);
		})
		.production([](auto&&) -> Value { return std::vector<std::shared_ptr<HexStringUnit>>(); })
		;
	_parser.rule("hex_or") // shared_ptr<HexStringUnit>
		.production("LP", "hex_or_body", "RP", [](auto&& args) -> Value {
			args[0].getTokenIt()->setType(HEX_ALT_LEFT_BRACKET);
			args[2].getTokenIt()->setType(HEX_ALT_RIGHT_BRACKET);
			return Value(std::make_shared<HexStringOr>(std::move(args[1].getMultipleHexStrings())));
		})
		;
	_parser.rule("hex_or_body") // vector<shared_ptr<yaramod::String>>
		.production("hex_string_body", [&](auto&& args) -> Value {
			std::vector<std::shared_ptr<HexString>> output;
			auto hexStr = std::make_shared<HexString>(_driver.currentStream(), std::move(args[0].getMultipleHexUnits()));
			output.push_back(std::move(hexStr));
			return std::move(output);
		})
		.production("hex_or_body", "HEX_OR", "hex_string_body", [&](auto&& args) -> Value {
			auto output = std::move(args[0].getMultipleHexStrings());
			auto hexStr = std::make_shared<HexString>(_driver.currentStream(), std::move(args[2].getMultipleHexUnits()));
			output.push_back(hexStr);
			return std::move(output);
		})
		;
	_parser.rule("hex_jump") // shared_ptr<HexStringUnit>
		.production("LSQB", "HEX_INTEGER", "RSQB", [](auto&& args) -> Value {
			args[0].getTokenIt()->setType(HEX_JUMP_LEFT_BRACKET);
			args[2].getTokenIt()->setType(HEX_JUMP_RIGHT_BRACKET);
			return Value(std::make_shared<HexStringJump>(args[1].getTokenIt(), args[1].getTokenIt()));
		})
		.production("LSQB", "HEX_INTEGER", "DASH", "HEX_INTEGER", "RSQB", [](auto&& args) -> Value {
			args[0].getTokenIt()->setType(HEX_JUMP_LEFT_BRACKET);
			args[4].getTokenIt()->setType(HEX_JUMP_RIGHT_BRACKET);
			return Value(std::make_shared<HexStringJump>(args[1].getTokenIt(), args[3].getTokenIt()));
		})
		.production("LSQB", "HEX_INTEGER", "DASH", "RSQB", [](auto&& args) -> Value {
			args[0].getTokenIt()->setType(HEX_JUMP_LEFT_BRACKET);
			args[3].getTokenIt()->setType(HEX_JUMP_RIGHT_BRACKET);
			return Value(std::make_shared<HexStringJump>(args[1].getTokenIt()));
		})
		.production("LSQB", "DASH", "RSQB", [](auto&& args) -> Value {
			args[0].getTokenIt()->setType(HEX_JUMP_LEFT_BRACKET);
			args[2].getTokenIt()->setType(HEX_JUMP_RIGHT_BRACKET);
			return Value(std::make_shared<HexStringJump>());
		})
		;

	_parser.rule("regexp") // shared_ptr<yaramod::String>
		.production("SLASH", "regexp_body", "SLASH", [&](auto&& args) -> Value {
			auto regexp_string = std::move(args[1].getYaramodString());
			std::static_pointer_cast<Regexp>(regexp_string)->setSuffixModifiers(args[2].getString().substr(1));
			return Value(std::move(regexp_string));
		})
		;
	_parser.rule("regexp_body") // shared_ptr<yaramod::String>
		.production("regexp_or", [&](auto&& args) -> Value { return Value(std::make_shared<Regexp>(_driver.currentStream(), std::move(args[0].getRegexpUnit()))); });

	_parser.rule("regexp_or") // shared_ptr<RegexpUnit>
		.production("regexp_concat", [](auto&& args) -> Value { return Value(std::make_shared<RegexpConcat>(std::move(args[0].getMultipleRegexpUnits()))); })
		.production("regexp_or", "REGEXP_OR", "regexp_concat", [](auto&& args) -> Value {
			std::shared_ptr<RegexpUnit> arg = std::move(args[0].getRegexpUnit());
			std::shared_ptr<RegexpUnit> concat = std::make_shared<RegexpConcat>(args[2].getMultipleRegexpUnits());
			return Value(std::make_shared<RegexpOr>(std::move(arg), std::move(concat)));
		})
		;
	_parser.rule("regexp_concat") // vector<shared_ptr<RegexpUnit>>
		.production("regexp_repeat", [](auto&& args) -> Value {
			std::vector<std::shared_ptr<yaramod::RegexpUnit>> output;
			output.push_back(std::move(args[0].getRegexpUnit()));
			return Value(std::move(output));
		})
		.production("regexp_concat", "regexp_repeat", [](auto&& args) -> Value {
			auto output = std::move(args[0].getMultipleRegexpUnits());
			output.push_back(std::move(args[1].getRegexpUnit()));
			return Value(std::move(output));
		})
		;
	_parser.rule("regexp_repeat") // shared_ptr<RegexpUnit>
		.production("regexp_single", "REGEXP_ITER", "regexp_greedy", [](auto&& args) -> Value {
			return Value(std::make_shared<RegexpIteration>(std::move(args[0].getRegexpUnit()), args[2].getBool()));
		})
		.production("regexp_single", "REGEXP_PITER", "regexp_greedy", [](auto&& args) -> Value {
			return Value(std::make_shared<RegexpPositiveIteration>(std::move(args[0].getRegexpUnit()), args[2].getBool()));
		})
		.production("regexp_single", "REGEXP_OPTIONAL", "regexp_greedy", [](auto&& args) -> Value {
			return Value(std::make_shared<RegexpOptional>(std::move(args[0].getRegexpUnit()), args[2].getBool()));
		})
		.production("regexp_single", "REGEXP_RANGE", "regexp_greedy", [&](auto&& args) -> Value {
			auto pair = std::move(args[1].getRegexpRangePair());
			if(!pair.first && !pair.second)
				error_handle("Range in regular expression does not have defined lower bound nor higher bound");
			if(pair.first && pair.second && pair.first.value() > pair.second.value())
				error_handle("Range in regular expression has greater lower bound than higher bound");
			return Value(std::make_shared<RegexpRange>(std::move(args[0].getRegexpUnit()), std::move(pair), args[2].getBool()));
		})
		.production("regexp_single", [](auto&& args) -> Value {
			return std::move(args[0]); //Value(std::move(args[0].getRegexpUnit()));
		})
		.production("REGEXP_WORD_BOUNDARY", [](auto&&) -> Value {
			return Value(std::make_shared<RegexpWordBoundary>());
		})
		.production("REGEXP_NON_WORD_BOUNDARY", [](auto&&) -> Value {
			return Value(std::make_shared<RegexpNonWordBoundary>());
		})
		.production("REGEXP_START_OF_LINE", [](auto&&) -> Value {
			return Value(std::make_shared<RegexpStartOfLine>());
		})
		.production("REGEXP_END_OF_LINE", [](auto&&) -> Value {
			return Value(std::make_shared<RegexpEndOfLine>());
		})
		;
	_parser.rule("regexp_greedy") // bool
		.production([](auto&&) -> Value { return true; })
		.production("REGEXP_OPTIONAL", [](auto&&) -> Value { return false; })
		;
	_parser.rule("regexp_single") // shared_ptr<yaramod::RegexpUnit>
		.production("LP", "regexp_or", "RP", [](auto&& args) -> Value { return Value(std::make_shared<RegexpGroup>(std::move(args[1].getRegexpUnit()))); })
		.production("REGEXP_ANY_CHAR", [](auto&&) -> Value { return Value(std::make_shared<RegexpAnyChar>()); })
		.production("REGEXP_CHAR", [](auto&& args) -> Value { return Value(std::make_shared<RegexpText>(std::move(args[0].getString()))); })
		.production("REGEXP_WORD_CHAR", [](auto&&) -> Value { return Value(std::make_shared<RegexpWordChar>()); })
		.production("REGEXP_NON_WORD_CHAR", [](auto&&) -> Value { return Value(std::make_shared<RegexpNonWordChar>()); })
		.production("REGEXP_SPACE", [](auto&&) -> Value { return Value(std::make_shared<RegexpSpace>()); })
		.production("REGEXP_NON_SPACE", [](auto&&) -> Value { return Value(std::make_shared<RegexpNonSpace>()); })
		.production("REGEXP_DIGIT", [](auto&&) -> Value { return Value(std::make_shared<RegexpDigit>()); })
		.production("REGEXP_NON_DIGIT", [](auto&&) -> Value { return Value(std::make_shared<RegexpNonDigit>()); })
		.production("REGEXP_CLASS", [](auto&& args) -> Value {
			std::string c = std::move(args[0].getString());
			if(c[0] == '^')
				return Value(std::make_shared<RegexpClass>(c.substr(1, c.length() - 1), true));
			else
				return Value(std::make_shared<RegexpClass>(std::move(c), false));
		})
		;

	_parser.rule("condition") // Expression::Ptr
		.production("CONDITION", "COLON", "expression", [](auto&& args) -> Value {
			return std::move(args[2]);
		})
		;
	_parser.rule("expression") // Expression::Ptr
		.production("boolean", [&](auto&& args) -> Value {
			auto output = std::make_shared<BoolLiteralExpression>(args[0].getTokenIt());
			output->setType(Expression::Type::Bool);
			return Value(std::move(output));
		})
		.production("string_id", [&](auto&& args) -> Value {
			TokenIt id = args[0].getTokenIt();
			if(!_driver.stringExists(id->getString()))
				error_handle("Reference to undefined string '" + id->getString() + "'");
			auto output = std::make_shared<StringExpression>(std::move(id));
			output->setType(Expression::Type::Bool);
			return Value(std::move(output));
		})
		.production("string_id", "AT", "primary_expression", [&](auto&& args) -> Value {
			TokenIt id = args[0].getTokenIt();
			if(!_driver.stringExists(id->getString()))
				error_handle("Reference to undefined string '" + id->getString() + "'");
			TokenIt op = args[1].getTokenIt();
			Expression::Ptr expr = args[2].getExpression();
			if(!expr->isInt())
				error_handle("Operator 'at' expects integer on the right-hand side of the expression");
			auto output = std::make_shared<StringAtExpression>(id, op, std::move(expr));
			output->setType(Expression::Type::Bool);
			return Value(std::move(output));
		})
		.production("string_id", "IN", "range", [&](auto&& args) -> Value {
			TokenIt id = args[0].getTokenIt();
			if(!_driver.stringExists(id->getString()))
				error_handle("Reference to undefined string '" + id->getString() + "'");
			TokenIt op = args[1].getTokenIt();
			Expression::Ptr range = args[2].getExpression();

			auto output = std::make_shared<StringInRangeExpression>(id, op, std::move(range));
			output->setType(Expression::Type::Bool);
			return Value(std::move(output));
		})
		.production(
			"FOR", "for_expression", "ID", [&](auto&& args) -> Value {
				auto symbol = std::make_shared<ValueSymbol>(args[2].getTokenIt()->getString(), Expression::Type::Int);
				if(!_driver.addLocalSymbol(symbol))
					error_handle("Redefinition of identifier '" + args[2].getTokenIt()->getString() + "'");
				return {};
			},
			"IN", "integer_set", "COLON", "LP", "expression", "RP", [&](auto&& args) -> Value {
				TokenIt for_token = args[0].getTokenIt();
				auto for_expr = std::move(args[1].getExpression());
				TokenIt id = args[2].getTokenIt();
				//
				TokenIt op_in = args[4].getTokenIt();
				auto set = std::move(args[5].getExpression());
				TokenIt lp = args[7].getTokenIt();
				auto expr = args[8].getExpression();
				TokenIt rp = args[9].getTokenIt();

				_driver.removeLocalSymbol(id->getString());
				lp->setType(TokenType::LP_WITH_SPACE_AFTER);
				rp->setType(TokenType::RP_WITH_SPACE_BEFORE);
				auto output = std::make_shared<ForIntExpression>(std::move(for_expr), id, std::move(set), std::move(expr), for_token, op_in, lp, rp);
				output->setType(Expression::Type::Bool);
				return Value(std::move(output));
			}
		)
		.production(
			"FOR", "for_expression", "OF", "string_set", [&](auto&& args) -> Value {
				if(_driver.isInStringLoop())
					error_handle("Nesting of for-loop over strings is not allowed");
				_driver.stringLoopEnter();
			},
			"COLON", "LP", "expression", "RP", [&](auto&& args) -> Value {
				TokenIt for_token = args[0].getTokenIt();
				auto for_expr = std::move(args[1].getExpression());
				TokenIt of = args[2].getTokenIt();
				auto set = std::move(args[3].getExpression());
				//
				TokenIt lp = args[6].getTokenIt();
				auto expr = args[7].getExpression();
				TokenIt rp = args[8].getTokenIt();

				lp->setType(TokenType::LP_WITH_SPACE_AFTER);
				rp->setType(TokenType::RP_WITH_SPACE_BEFORE);
				auto output = std::make_shared<ForStringExpression>(for_token, std::move(for_expr), of, std::move(set), lp, std::move(expr), rp);
				output->setType(Expression::Type::Bool);
				_driver.stringLoopLeave();
				return Value(std::move(output));
			}
		)
		.production("for_expression", "OF", "string_set", [&](auto&& args) -> Value {
			auto for_expr = std::move(args[0].getExpression());
			TokenIt of = args[1].getTokenIt();
			auto set = std::move(args[2].getExpression());
			auto output = std::make_shared<OfExpression>(std::move(for_expr), of, std::move(set));
			output->setType(Expression::Type::Bool);
			return Value(std::move(output));
		})
		.production("NOT", "expression", [&](auto&& args) -> Value {
			TokenIt not_token = args[0].getTokenIt();
			auto expr = std::move(args[1].getExpression());
			auto output = std::make_shared<NotExpression>(not_token, std::move(expr));
			output->setType(Expression::Type::Bool);
			return Value(std::move(output));
		})
		.production("expression", "AND", "expression", [&](auto&& args) -> Value {
			auto left = std::move(args[0].getExpression());
			TokenIt and_token = args[1].getTokenIt();
			auto right = std::move(args[2].getExpression());
			auto output = std::make_shared<AndExpression>(std::move(left), and_token, std::move(right));
			output->setType(Expression::Type::Bool);
			return Value(std::move(output));
		})
		.production("expression", "OR", "expression", [&](auto&& args) -> Value {
			auto left = std::move(args[0].getExpression());
			TokenIt or_token = args[1].getTokenIt();
			auto right = std::move(args[2].getExpression());
			auto output = std::make_shared<OrExpression>(std::move(left), or_token, std::move(right));
			output->setType(Expression::Type::Bool);
			return Value(std::move(output));
		})
		.production("primary_expression", "LT", "primary_expression", [&](auto&& args) -> Value {
			auto left = std::move(args[0].getExpression());
			TokenIt op_token = args[1].getTokenIt();
			auto right = std::move(args[2].getExpression());
			auto output = std::make_shared<LtExpression>(std::move(left), op_token, std::move(right));
			output->setType(Expression::Type::Bool);
			return Value(std::move(output));
		})
		.production("primary_expression", "GT", "primary_expression", [&](auto&& args) -> Value {
			auto left = std::move(args[0].getExpression());
			TokenIt op_token = args[1].getTokenIt();
			auto right = std::move(args[2].getExpression());
			auto output = std::make_shared<GtExpression>(std::move(left), op_token, std::move(right));
			output->setType(Expression::Type::Bool);
			return Value(std::move(output));
		})
		.production("primary_expression", "LE", "primary_expression", [&](auto&& args) -> Value {
			auto left = std::move(args[0].getExpression());
			TokenIt op_token = args[1].getTokenIt();
			auto right = std::move(args[2].getExpression());
			auto output = std::make_shared<LeExpression>(std::move(left), op_token, std::move(right));
			output->setType(Expression::Type::Bool);
			return Value(std::move(output));
		})
		.production("primary_expression", "GE", "primary_expression", [&](auto&& args) -> Value {
			auto left = std::move(args[0].getExpression());
			TokenIt op_token = args[1].getTokenIt();
			auto right = std::move(args[2].getExpression());
			auto output = std::make_shared<GeExpression>(std::move(left), op_token, std::move(right));
			output->setType(Expression::Type::Bool);
			return Value(std::move(output));
		})
		.production("primary_expression", "EQ", "primary_expression", [&](auto&& args) -> Value {
			auto left = std::move(args[0].getExpression());
			TokenIt op_token = args[1].getTokenIt();
			auto right = std::move(args[2].getExpression());
			auto output = std::make_shared<EqExpression>(std::move(left), op_token, std::move(right));
			output->setType(Expression::Type::Bool);
			return Value(std::move(output));
		})
		.production("primary_expression", "NEQ", "primary_expression", [&](auto&& args) -> Value {
			auto left = std::move(args[0].getExpression());
			TokenIt op_token = args[1].getTokenIt();
			auto right = std::move(args[2].getExpression());
			auto output = std::make_shared<NeqExpression>(std::move(left), op_token, std::move(right));
			output->setType(Expression::Type::Bool);
			return Value(std::move(output));
		})
		.production("primary_expression", "CONTAINS", "primary_expression", [&](auto&& args) -> Value {
			auto left = std::move(args[0].getExpression());
			TokenIt op_token = args[1].getTokenIt();
			auto right = std::move(args[2].getExpression());
			if(!left->isString())
				error_handle("operator 'contains' expects string on the left-hand side of the expression");
			if(!right->isString())
				error_handle("operator 'contains' expects string on the right-hand side of the expression");
			auto output = std::make_shared<ContainsExpression>(std::move(left), op_token, std::move(right));
			output->setType(Expression::Type::Bool);
			return Value(std::move(output));
		})
		.production("primary_expression", "MATCHES", "regexp", [&](auto&& args) -> Value {
			auto left = std::move(args[0].getExpression());
			TokenIt op_token = args[1].getTokenIt();
			auto right = std::move(args[2].getYaramodString());
			if(!left->isString())
				error_handle("operator 'matches' expects string on the left-hand side of the expression");
			auto regexp_expression = std::make_shared<RegexpExpression>(std::move(right));
			auto output = std::make_shared<MatchesExpression>(std::move(left), op_token, std::move(regexp_expression));
			output->setType(Expression::Type::Bool);
			return Value(std::move(output));
		})
		.production("primary_expression", [&](auto&& args) -> Value {
			return std::move(args[0]);
		}).precedence(0, pog::Associativity::Left)
		.production("LP", "expression", "RP", [&](auto&& args) -> Value {
			auto expr = std::move(args[1].getExpression());
			auto type = expr->getType();
			auto output = std::make_shared<ParenthesesExpression>(args[0].getTokenIt(), std::move(expr), args[2].getTokenIt());
			output->setType(type);
			return Value(std::move(output));
		})
		;

	_parser.rule("primary_expression") // Expression::Ptr
		.production("LP", "primary_expression", "RP", [&](auto&& args) -> Value {
			auto type = args[1].getExpression()->getType();
			auto output = std::make_shared<ParenthesesExpression>(args[0].getTokenIt(), std::move(args[1].getExpression()), args[2].getTokenIt());
			output->setType(type);
			return Value(std::move(output));
		})
		.production("FILESIZE", [&](auto&& args) -> Value {
			auto output = std::make_shared<FilesizeExpression>(args[0].getTokenIt());
			output->setType(Expression::Type::Int);
			return Value(std::move(output));
		})
		.production("ENTRYPOINT", [&](auto&& args) -> Value {
			auto output = std::make_shared<EntrypointExpression>(args[0].getTokenIt());
			output->setType(Expression::Type::Int);
			return Value(std::move(output));
		})
		.production("integer_token", [&](auto&& args) -> Value {
			auto output = std::make_shared<IntLiteralExpression>(args[0].getTokenIt());
			output->setType(Expression::Type::Int);
			return Value(std::move(output));
		})
		.production("DOUBLE", [&](auto&& args) -> Value {
			auto output = std::make_shared<DoubleLiteralExpression>(args[0].getTokenIt());
			output->setType(Expression::Type::Float);
			return Value(std::move(output));
		})
		.production("STRING_LITERAL", [&](auto&& args) -> Value {
			auto output = std::make_shared<StringLiteralExpression>(args[0].getTokenIt());
			output->setType(Expression::Type::String);
			return Value(std::move(output));
		})
		.production("STRING_COUNT", [&](auto&& args) -> Value {
			// Replace '#' for '$' to get string id
			auto stringId = args[0].getTokenIt()->getString();
			stringId[0] = '$';

			if (!_driver.stringExists(stringId))
				error_handle("Reference to undefined string '" + args[0].getTokenIt()->getString() + "'");

			auto output = std::make_shared<StringCountExpression>(args[0].getTokenIt());
			output->setType(Expression::Type::Int);
			return Value(std::move(output));
		})
		.production("STRING_OFFSET", [&](auto&& args) -> Value {
			// Replace '@' for '$' to get string id
			auto stringId = args[0].getTokenIt()->getString();
			stringId[0] = '$';

			if (!_driver.stringExists(stringId))
				error_handle("Reference to undefined string '" + args[0].getTokenIt()->getString() + "'");

			auto output = std::make_shared<StringOffsetExpression>(args[0].getTokenIt());
			output->setType(Expression::Type::Int);
			return Value(std::move(output));
		})
		.production("STRING_OFFSET", "LSQB", "primary_expression", "RSQB", [&](auto&& args) -> Value {
			// Replace '@' for '$' to get string id
			auto stringId = args[0].getTokenIt()->getString();
			stringId[0] = '$';

			if (!_driver.stringExists(stringId))
				error_handle("Reference to undefined string '" + args[0].getTokenIt()->getString() + "'");

			auto output = std::make_shared<StringOffsetExpression>(args[0].getTokenIt(), std::move(args[2].getExpression()));
			output->setType(Expression::Type::Int);
			return Value(std::move(output));
		})
		.production("STRING_LENGTH", [&](auto&& args) -> Value {
			// Replace '!' for '$' to get string id
			auto stringId = args[0].getTokenIt()->getString();
			stringId[0] = '$';

			if (!_driver.stringExists(stringId))
				error_handle("Reference to undefined string '" + args[0].getTokenIt()->getString() + "'");

			auto output = std::make_shared<StringLengthExpression>(args[0].getTokenIt());
			output->setType(Expression::Type::Int);
			return Value(std::move(output));
		})
		.production("STRING_LENGTH", "LSQB", "primary_expression", "RSQB", [&](auto&& args) -> Value {
			// Replace '!' for '$' to get string id
			auto stringId = args[0].getTokenIt()->getString();
			stringId[0] = '$';

			if (!_driver.stringExists(stringId))
				error_handle("Reference to undefined string '" + args[0].getTokenIt()->getString() + "'");

			auto output = std::make_shared<StringLengthExpression>(args[0].getTokenIt(), std::move(args[2].getExpression()));
			output->setType(Expression::Type::Int);
			return Value(std::move(output));
		})
		.production("MINUS", "primary_expression", [&](auto&& args) -> Value {
			auto right = args[1].getExpression();
			if(!right->isInt() && !right->isFloat())
			{
				error_handle("unary minus expects integer or float type");
			}
			auto type = right->getType();
			args[0].getTokenIt()->setType(UNARY_MINUS);
			auto output = std::make_shared<UnaryMinusExpression>(args[0].getTokenIt(), std::move(right));
			output->setType(type);
			return Value(std::move(output));
		}).precedence(3, pog::Associativity::Right)
		.production("primary_expression", "PLUS", "primary_expression", [&](auto&& args) -> Value {
			auto left = args[0].getExpression();
			auto right = args[2].getExpression();
			if(!left->isInt() && !left->isFloat())
				error_handle("operator '+' expects integer or float on the left-hand side");
			if(!right->isInt() && !right->isFloat())
				error_handle("operator '+' expects integer or float on the right-hand side");
			auto type = (left->isInt() && right->isInt()) ? Expression::Type::Int : Expression::Type::Float;
			auto output = std::make_shared<PlusExpression>(std::move(left), args[1].getTokenIt(), std::move(right));
			output->setType(type);
			return Value(std::move(output));
		})
		.production("primary_expression", "MINUS", "primary_expression", [&](auto&& args) -> Value {
			auto left = args[0].getExpression();
			auto right = args[2].getExpression();
			if(!left->isInt() && !left->isFloat())
				error_handle("operator '-' expects integer or float on the left-hand side");
			if(!right->isInt() && !right->isFloat())
				error_handle("operator '-' expects integer or float on the right-hand side");
			auto type = (left->isInt() && right->isInt()) ? Expression::Type::Int : Expression::Type::Float;
			auto output = std::make_shared<MinusExpression>(std::move(left), args[1].getTokenIt(), std::move(right));
			output->setType(type);
			return Value(std::move(output));
		})
		.production("primary_expression", "MULTIPLY", "primary_expression", [&](auto&& args) -> Value {
			auto left = args[0].getExpression();
			auto right = args[2].getExpression();
			if(!left->isInt() && !left->isFloat())
				error_handle("operator '*' expects integer or float on the left-hand side");
			if(!right->isInt() && !right->isFloat())
				error_handle("operator '*' expects integer or float on the right-hand side");
			auto type = (left->isInt() && right->isInt()) ? Expression::Type::Int : Expression::Type::Float;
			auto output = std::make_shared<MultiplyExpression>(std::move(left), args[1].getTokenIt(), std::move(right));
			output->setType(type);
			return Value(std::move(output));
		})
		.production("primary_expression", "DIVIDE", "primary_expression", [&](auto&& args) -> Value {
			auto left = args[0].getExpression();
			auto right = args[2].getExpression();
			if(!left->isInt() && !left->isFloat())
				error_handle("operator '\\' expects integer or float on the left-hand side");
			if(!right->isInt() && !right->isFloat())
				error_handle("operator '\\' expects integer or float on the right-hand side");
			auto type = (left->isInt() && right->isInt()) ? Expression::Type::Int : Expression::Type::Float;
			auto output = std::make_shared<DivideExpression>(std::move(left), args[1].getTokenIt(), std::move(right));
			output->setType(type);
			return Value(std::move(output));
		})
		.production("primary_expression", "MODULO", "primary_expression", [&](auto&& args) -> Value {
			auto left = args[0].getExpression();
			auto right = args[2].getExpression();
			if(!left->isInt() && !left->isFloat())
				error_handle("operator '%' expects integer or float on the left-hand side");
			if(!right->isInt() && !right->isFloat())
				error_handle("operator '%' expects integer or float on the right-hand side");
			auto output = std::make_shared<ModuloExpression>(std::move(left), args[1].getTokenIt(), std::move(right));
			output->setType(Expression::Type::Int);
			return Value(std::move(output));
		})
		.production("primary_expression", "BITWISE_XOR", "primary_expression", [&](auto&& args) -> Value {
			auto left = args[0].getExpression();
			auto right = args[2].getExpression();
			if(!left->isInt() && !left->isFloat())
				error_handle("operator '^' expects integer or float on the left-hand side");
			if(!right->isInt() && !right->isFloat())
				error_handle("operator '^' expects integer or float on the right-hand side");
			auto output = std::make_shared<BitwiseXorExpression>(std::move(left), args[1].getTokenIt(), std::move(right));
			output->setType(Expression::Type::Int);
			return Value(std::move(output));
		})
		.production("primary_expression", "BITWISE_AND", "primary_expression", [&](auto&& args) -> Value {
			auto left = args[0].getExpression();
			auto right = args[2].getExpression();
			if(!left->isInt() && !left->isFloat())
				error_handle("operator '&' expects integer or float on the left-hand side");
			if(!right->isInt() && !right->isFloat())
				error_handle("operator '&' expects integer or float on the right-hand side");
			auto output = std::make_shared<BitwiseAndExpression>(std::move(left), args[1].getTokenIt(), std::move(right));
			output->setType(Expression::Type::Int);
			return Value(std::move(output));
		})
		.production("primary_expression", "BITWISE_OR", "primary_expression", [&](auto&& args) -> Value {
			auto left = args[0].getExpression();
			auto right = args[2].getExpression();
			if(!left->isInt() && !left->isFloat())
				error_handle("operator '|' expects integer or float on the left-hand side");
			if(!right->isInt() && !right->isFloat())
				error_handle("operator '|' expects integer or float on the right-hand side");
			auto output = std::make_shared<BitwiseOrExpression>(std::move(left), args[1].getTokenIt(), std::move(right));
			output->setType(Expression::Type::Int);
			return Value(std::move(output));
		})
		.production("BITWISE_NOT", "primary_expression", [&](auto&& args) -> Value {
			auto right = args[1].getExpression();
			if(!right->isInt())
				error_handle("bitwise not expects integer");
			auto output = std::make_shared<BitwiseNotExpression>(args[0].getTokenIt(), std::move(right));
			output->setType(Expression::Type::Int);
			return Value(std::move(output));
		})
		.production("primary_expression", "SHIFT_LEFT", "primary_expression", [&](auto&& args) -> Value {
			auto left = args[0].getExpression();
			auto right = args[2].getExpression();
			if(!left->isInt() && !left->isFloat())
				error_handle("operator '<<' expects integer on the left-hand side");
			if(!right->isInt() && !right->isFloat())
				error_handle("operator '<<' expects integer on the right-hand side");
			auto output = std::make_shared<ShiftLeftExpression>(std::move(left), args[1].getTokenIt(), std::move(right));
			output->setType(Expression::Type::Int);
			return Value(std::move(output));
		})
		.production("primary_expression", "SHIFT_RIGHT", "primary_expression", [&](auto&& args) -> Value {
			auto left = args[0].getExpression();
			auto right = args[2].getExpression();
			if(!left->isInt() && !left->isFloat())
				error_handle("operator '>>' expects integer on the left-hand side");
			if(!right->isInt() && !right->isFloat())
				error_handle("operator '>>' expects integer on the right-hand side");
			auto output = std::make_shared<ShiftRightExpression>(std::move(left), args[1].getTokenIt(), std::move(right));
			output->setType(Expression::Type::Int);
			return Value(std::move(output));
		})
		.production("INTEGER_FUNCTION", "LP", "primary_expression", "RP", [&](auto&& args) -> Value {
			if(!args[2].getExpression()->isInt())
				error_handle("operator '" + args[0].getTokenIt()->getString() + "' expects integer");
			auto output = std::make_shared<IntFunctionExpression>(std::move(args[0].getTokenIt()), std::move(args[1].getTokenIt()), std::move(args[2].getExpression()), std::move(args[3].getTokenIt()));
			output->setType(Expression::Type::Int);
			return Value(std::move(output));
		})
		.production("identifier", [&](auto&& args) -> Value {
			return Value(std::move(args[0]));
		})
		.production("regexp", [&](auto&& args) -> Value {
			auto output = std::make_shared<RegexpExpression>(std::move(args[0].getYaramodString()));
			output->setType(Expression::Type::Regexp);
			return Value(std::move(output));
		})
		;// end of primary_expression

	_parser.rule("identifier") // Expression::Ptr
		.production("ID", [&](auto&& args) -> Value {
			auto symbol = _driver.findSymbol(args[0].getTokenIt()->getString());
			if(!symbol)
				error_handle("Unrecognized identifier '" + args[0].getTokenIt()->getString() + "' referenced");
			TokenIt symbol_token = args[0].getTokenIt();
			symbol_token->setValue(symbol, symbol->getName());
			auto output = std::make_shared<IdExpression>(symbol_token);
			output->setType(symbol->getDataType());
			return Value(std::move(output));
		})
		.production("identifier", "DOT", "ID", [&](auto&& args) -> Value {
			const auto& expr = args[0].getExpression();
			if(!expr->isObject())
				error_handle("Identifier '" + expr->getText() + "' is not an object");

			auto parentSymbol = std::static_pointer_cast<const IdExpression>(expr)->getSymbol();
			if(!parentSymbol->isStructure())
				error_handle("Identifier '" + parentSymbol->getName() + "' is not a structure");
			auto structParentSymbol = std::static_pointer_cast<const StructureSymbol>(parentSymbol);

			TokenIt symbol_token = args[2].getTokenIt();
			auto attr = structParentSymbol->getAttribute(symbol_token->getString());
			if (!attr)
				error_handle("Unrecognized identifier '" + symbol_token->getString() + "' referenced");

			auto symbol = attr.value();
			symbol_token->setValue(symbol, symbol->getName());
			symbol_token->setType(symbol->getTokenType());
			auto output = std::make_shared<StructAccessExpression>(symbol_token, std::move(expr), args[1].getTokenIt());
			output->setType(symbol->getDataType());
			return Value(std::move(output));
		})
		.production("identifier", "LSQB", "primary_expression", "RSQB", [&](auto&& args) -> Value {
			const auto& expr = args[0].getExpression();
			if(!expr->isObject())
				error_handle("Identifier '" + expr->getText() + "' is not an object");

			auto parentSymbol = std::static_pointer_cast<const IdExpression>(expr)->getSymbol();
			if (!parentSymbol->isArray() && !parentSymbol->isDictionary())
				error_handle("Identifier '" + parentSymbol->getName() + "' is not an array nor dictionary");

			auto iterParentSymbol = std::static_pointer_cast<const IterableSymbol>(parentSymbol);
			auto output = std::make_shared<ArrayAccessExpression>(iterParentSymbol->getStructuredElementType(), std::move(expr), std::move(args[2].getExpression()));
			output->setType(iterParentSymbol->getElementType());
			return Value(std::move(output));
		})
		.production("identifier", "LP", "arguments", "RP", [&](auto&& args) -> Value {
			const auto& expr = args[0].getExpression();
			if (!expr->isObject())
				error_handle("Identifier '" + expr->getText() + "' is not an object");

			auto parentSymbol = std::static_pointer_cast<const IdExpression>(expr)->getSymbol();
			if (!parentSymbol->isFunction())
				error_handle("Identifier '" + parentSymbol->getName() + "' is not a function");

			auto funcParentSymbol = std::static_pointer_cast<const FunctionSymbol>(parentSymbol);

			// Make copy of just argument types because symbols are not aware of expressions
			std::vector<Expression::Type> argTypes;
			auto arguments = std::move(args[2].getMultipleExpressions());
			std::for_each(arguments.begin(), arguments.end(),
				[&argTypes](const Expression::Ptr& e)
				{
					argTypes.push_back(e->getType());
				});

			if (!funcParentSymbol->overloadExists(argTypes))
			{
				std::cerr << "Unexpected argument types for function " << funcParentSymbol->getName() << " ( ";
				std::for_each(arguments.begin(), arguments.end(),
					[](const Expression::Ptr& e)
					{
						std::cerr << e->getTypeString() << " ";
					});
				std::cerr << ")" << std::endl;
				error_handle("No matching overload of function '" + funcParentSymbol->getName() + "' for these types of parameters");
			}

			auto output = std::make_shared<FunctionCallExpression>(std::move(expr), args[1].getTokenIt(), std::move(arguments), args[3].getTokenIt());
			output->setType(funcParentSymbol->getReturnType());
			return Value(std::move(output));
		})
		;
	_parser.rule("arguments") // vector<Expression::Ptr>
		.production("arguments", "COMMA", "expression", [&](auto&& args) -> Value {
			auto output = std::move(args[0].getMultipleExpressions());
			output.push_back(std::move(args[2].getExpression()));
			return Value(std::move(output));
		})
		.production("expression", [&](auto&& args) -> Value {
			std::vector<Expression::Ptr> output;
			output.push_back(std::move(args[0].getExpression()));
			return Value(std::move(output));
		})
		.production([&](auto&&) -> Value {
			std::vector<Expression::Ptr> output;
			return Value(std::move(output));
		})
		;
	_parser.rule("integer_token") // TokenIt
		.production("INTEGER", [&](auto&& args) -> Value {
			return std::move(args[0]);
		});
	_parser.rule("range") // Expression::Ptr
		.production("LP", "primary_expression", "RANGE", "primary_expression", "RP", [&](auto&& args) -> Value {
			auto left = args[1].getExpression();
			auto right = args[3].getExpression();
			if(!left->isInt())
				error_handle("operator '..' expects integer as lower bound of the interval");
			if(!right->isInt())
				error_handle("operator '..' expects integer as upper bound of the interval");
			return Value(std::make_shared<RangeExpression>(args[0].getTokenIt(), std::move(left), args[2].getTokenIt(), std::move(right), args[4].getTokenIt()));
		})
		;
	_parser.rule("for_expression") // Expression::Ptr
		.production("primary_expression", [](auto&& args) -> Value { return std::move(args[0]); })
		.production("ALL", [](auto&& args) -> Value { return Value(std::make_shared<AllExpression>(args[0].getTokenIt())); })
		.production("ANY", [](auto&& args) -> Value { return Value(std::make_shared<AnyExpression>(args[0].getTokenIt())); })
		;

	_parser.rule("integer_set") // Expression::Ptr
		.production("LP", "integer_enumeration", "RP", [&](auto&& args) -> Value {
			auto lp = args[0].getTokenIt();
			auto rp = args[2].getTokenIt();
			lp->setType(LP_ENUMERATION);
			rp->setType(RP_ENUMERATION);
			return Value(std::make_shared<SetExpression>(lp, std::move(args[1].getMultipleExpressions()), rp));
		})
		.production("range", [&](auto&& args) -> Value {
			return std::move(args[0]);
		})
		;
	_parser.rule("integer_enumeration") // vector<Expression::Ptr>
		.production("primary_expression", [&](auto&& args) -> Value {
			auto expr = args[0].getExpression();
			if(!expr->isInt())
				error_handle("integer set expects integer type");
			return Value(std::vector<Expression::Ptr> {std::move(expr)});
		})
		.production("integer_enumeration", "COMMA", "primary_expression", [&](auto&& args) -> Value {
			auto expr = args[2].getExpression();
			if(!expr->isInt())
				error_handle("integer set expects integer type");
			auto output = std::move(args[0].getMultipleExpressions());
			output.push_back(std::move(expr));
			return Value(std::move(output));
		})
		;
	_parser.rule("string_set") // Expression::Ptr
		.production("LP", "string_enumeration", "RP", [&](auto&& args) -> Value {
			TokenIt lp = args[0].getTokenIt();
			lp->setType(LP_ENUMERATION);
			TokenIt rp = args[2].getTokenIt();
			rp->setType(RP_ENUMERATION);
			return Value(std::make_shared<SetExpression>(lp, std::move(args[1].getMultipleExpressions()), rp));
		})
		.production("THEM", [&](auto&& args) -> Value {
			return Value(std::make_shared<ThemExpression>(args[0].getTokenIt()));
		})
		;
	_parser.rule("string_enumeration") // vector<Expression::Ptr>
		.production("string_id", [&](auto&& args) -> Value {
			TokenIt id = args[0].getTokenIt();
			if(!_driver.stringExists(id->getPureText()))
				error_handle("Reference to undefined string '" + id->getPureText() + "'");
			return std::vector<Expression::Ptr>{std::make_shared<StringExpression>(id)};
		})
		.production("STRING_ID_WILDCARD", [&](auto&& args) -> Value {
			TokenIt id = args[0].getTokenIt();
			if(!_driver.stringExists(id->getPureText()))
				error_handle("No string matched with wildcard '" + id->getPureText() + "'");
			return std::vector<Expression::Ptr>{std::make_shared<StringWildcardExpression>(id)};
		})
		.production("string_enumeration", "COMMA", "string_id", [&](auto&& args) -> Value {
			TokenIt id = args[2].getTokenIt();
			if(!_driver.stringExists(id->getPureText()))
				error_handle("Reference to undefined string '" + id->getPureText() + "'");
			auto output = std::move(args[0].getMultipleExpressions());
			output.push_back(std::make_shared<StringExpression>(id));
			return Value(std::move(output));
		})
		.production("string_enumeration", "COMMA", "STRING_ID_WILDCARD", [&](auto&& args) -> Value {
			TokenIt id = args[2].getTokenIt();
			if(!_driver.stringExists(id->getPureText()))
				error_handle("No string matched with wildcard '" + id->getPureText() + "'");
			auto output = std::move(args[0].getMultipleExpressions());
			output.push_back(std::make_shared<StringWildcardExpression>(id));
			return std::move(output);
		})
		;
}

bool PogParser::prepareParser()
{
	auto report = _parser.prepare();
	pog::HtmlReport html(_parser);
	html.save("html_index_commented.html");
	if(!report)
	{
		std::cerr << "Parser initialization failed" << std::endl;
		fmt::print("{}\n", report.to_string());
		return false;
	}
	return true;
}

// void PogParser::includeFile(std::stringstream* input)
// {

// }

void PogParser::enter_state(const std::string& state)
{
	_parser.enter_tokenizer_state(state);
}

void PogParser::parse()
{
	try
	{
		auto result = _parser.parse(*_input);
		if (!result)
	   {
	      std::cerr << "Error" << std::endl;
	      return;
	   }
	}
	catch(const pog::SyntaxError& err)
	{
		throw ParserError(err.what());
	}
}

/**
 * Constructor.
 *
 * @param filePath Input file path.
 * @param parserMode Parsing mode.
 */
ParserDriver::ParserDriver(const std::string& filePath, ParserMode parserMode) : _mode(parserMode), _pog_parser(*this),
	/*_loc(nullptr), */_valid(true), _filePath(), _inputFile(), _currentStrings(),
	_stringLoop(false), _localSymbols(), _startOfRule(0), _anonStringCounter(0)
{
	// Uncomment for debugging
	// See also occurrences of 'debugging' in parser.y to enable it
	// _parser.set_debug_level(1);

	// When creating ParserDriver from real file (not from some stringstream) we need to somehow tell lexer which file to process
	// yy::Lexer is not copyable nor assignable so we need to hack it through includes
	if (!includeFileImpl(filePath, std::make_shared<TokenStream>()))
		_valid = false;
	_file = std::move(YaraFile(_tokenStreams.top()));
}

/**
 * Constructor.
 *
 * @param input Input stream.
 * @param parserMode Parsing mode.
 */
ParserDriver::ParserDriver(std::istream& input, ParserMode parserMode) : _mode(parserMode), _pog_parser(*this),
	/*_loc(nullptr),  */_valid(true), _filePath(), _inputFile(), _currentStrings(),
	_stringLoop(false), _localSymbols()
{
	// Uncomment for debugging
	// See also occurrences of 'debugging' in parser.y to enable it
	// _parser.set_debug_level(1);

	_tokenStreams.push(std::make_shared<TokenStream>());
	_file = YaraFile(_tokenStreams.top());

	_pog_parser.setInput(&input);
}

/**
 * Returns the location in the file.
 *
 * @return Location.
 */
// const yy::location& ParserDriver::getLocation() const
// {
// 	return _loc;
// }

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

	//POG:
	_pog_parser.parse();
	bool output = true;

	// std::cout << "TokenStream when getParsedFile(): " << std::endl;
	// std::cout << *_file.getTokenStream() << "'" << std::endl;
	return output;
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
	// _loc.lines();
}

/**
 * Moves given number of columns further.
 *
 * @param moveLength Number of columns to move.
 */
void ParserDriver::moveLocation(std::uint64_t moveLength)
{
	// _loc.step();
	// _loc += moveLength;
}

/**
 * Includes file into input stream as it would be in place of @c include directive.
 *
 * @param includePath Path of file to include.
 *
 * @return @c true if include succeeded, otherwise @c false.
 */
bool ParserDriver::includeFile(const std::string& includePath, std::shared_ptr<TokenStream> substream)
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

	return includeFileImpl(totalPath, substream);
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
		assert(!_tokenStreams.empty());
		_tokenStreams.pop();
		_includedFiles.pop_back();
		_includedFileNames.pop_back();
		// _loc = _includedFileLocs.back();
		// _includedFileLocs.pop_back();
	}

	// return _lexer.includeEnd();
	return true;
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
	addRule(std::make_unique<Rule>(std::move(rule)));
}

/**
 * Adds the rule into the YARA file and properly sets up its location.
 *
 * @param rule Rule to add.
 */
void ParserDriver::addRule(std::unique_ptr<Rule>&& rule)
{
	if (!_includedFileNames.empty())
		rule->setLocation(_includedFileNames.back(), _startOfRule);
	bool success = _parsed_rule_names.insert(rule->getName()).second;
	if(!success)
		throw ParserError(std::string("Error at <TODO>: Redefinition of rule "+rule->getName()));
	else
		_file.addRule(std::move(rule));
}

// void ParserDriver::finishRule()
// {
//    std::unique_ptr<Rule> rule = builder.get();
//    addRule(std::move(rule));
// }

/**
 * Marks the line number where the rule starts.
 */
void ParserDriver::markStartOfRule()
{
	// _startOfRule = getLocation().end.line;
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


void ParserDriver::addComment(TokenIt comment)
{
	assert(comment->getType() == TokenType::COMMENT || comment->getType() == TokenType::ONELINE_COMMENT);
	_comments.push_back(comment);
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

bool ParserDriver::includeFileImpl(const std::string& includePath, std::shared_ptr<TokenStream> substream)//TODO: upravit
{
	if (_mode == ParserMode::IncludeGuarded && isAlreadyIncluded(includePath))
		return true;

	// We need to allocate ifstreams dynamically because they are not copyable and we need to store them
	// in vector to prolong their lifetime because of flex.
	auto includedFile = std::make_unique<std::ifstream>(includePath);
	if (!includedFile->is_open())
		return false;

	// _lexer.includeFile(includedFile.get());

	_pog_parser.setInput(includedFile.get());

	_tokenStreams.push(substream);
	_includedFiles.push_back(std::move(includedFile));
	_includedFileNames.push_back(includePath);
	// _includedFileLocs.push_back(_loc);
	_includedFilesCache.emplace(absolutePath(includePath));

	// Reset location se we can keep track of line numbers in included files
	// _loc.begin.initialize(_loc.begin.filename, 1, 1);
	// _loc.end.initialize(_loc.end.filename, 1, 1);
	return true;
}

} //namespace yaramod
