/**
 * @file src/parser/parser_driver.cpp
 * @brief Implementation of class ParserDriver.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "yaramod/parser/parser_driver.h"
#include "yaramod/types/expressions.h"
#include "yaramod/types/plain_string.h"
#include "yaramod/types/hex_string.h"
#include "yaramod/types/regexp.h"
#include "yaramod/types/token_type.h"
#include "yaramod/utils/filesystem_operations.h"


// Uncomment for advanced debugging with HtmlReport:
// #include <pog/html_report.h>

namespace yaramod {

void error_handle(const Location& location, const std::string& msg)
{
	std::stringstream err;
	err << "Error at " << location << ": " << msg;
	throw ParserError(err.str());
}

template <typename... Args>
TokenIt ParserDriver::emplace_back(Args&&... args)
{
	TokenIt tokenIt = currentFileContext()->getTokenStream()->emplace_back(args...);
	tokenIt->setLocation(currentFileContext()->getLocation());
	return tokenIt;
}

void ParserDriver::defineTokens()
{
	//define global action for counting the line/character position
	_parser.global_tokenizer_action([&](std::string_view str) {
		currentFileContext()->getLocation().addColumn(str.length());
	});

	_parser.token("\r\n").action([&](std::string_view) -> Value {
		currentFileContext()->getTokenStream()->setNewLineChar("\r\n");
		TokenIt t = emplace_back(TokenType::NEW_LINE, "\r\n");
		_indent.clear();
		currentFileContext()->getLocation().addLine();
		return t;
	});
	_parser.token("\n").action([&](std::string_view) -> Value {
		currentFileContext()->getTokenStream()->setNewLineChar("\n");
		TokenIt t = emplace_back(TokenType::NEW_LINE, "\n");
		_indent.clear();
		currentFileContext()->getLocation().addLine();
		return t;
	});
	_parser.token("[ \t]+").states("@default", "$hexstr_jump", "$hexstr").action([&](std::string_view str) -> Value { // spaces, tabulators
		_indent += std::string{str};
		return {};
	});

	_parser.token(R"(\.\.)").symbol("RANGE").description("integer range").action([&](std::string_view str) -> Value { return emplace_back(TokenType::DOUBLE_DOT, std::string{str}); });
	_parser.token(R"(\.)").symbol("DOT").description(".").action([&](std::string_view str) -> Value { return emplace_back(TokenType::DOT, std::string{str}); })
		.precedence(15, pog::Associativity::Left);
	_parser.token("<").symbol("LT").description("<").action([&](std::string_view str) -> Value { return emplace_back(TokenType::LT, std::string{str}); })
		.precedence(10, pog::Associativity::Left);
	_parser.token(">").symbol("GT").description(">").action([&](std::string_view str) -> Value { return emplace_back(TokenType::GT, std::string{str}); })
		.precedence(10, pog::Associativity::Left);
	_parser.token("<=").symbol("LE").description("<=").action([&](std::string_view str) -> Value { return emplace_back(TokenType::LE, std::string{str}); })
		.precedence(10, pog::Associativity::Left);
	_parser.token(">=").symbol("GE").description(">=").action([&](std::string_view str) -> Value { return emplace_back(TokenType::GE, std::string{str}); })
		.precedence(10, pog::Associativity::Left);
	_parser.token("==").symbol("EQ").description("==").action([&](std::string_view str) -> Value { return emplace_back(TokenType::EQ, std::string{str}); })
		.precedence(9, pog::Associativity::Left);
	_parser.token("!=").symbol("NEQ").description("!=").action([&](std::string_view str) -> Value { return emplace_back(TokenType::NEQ, std::string{str}); })
		.precedence(9, pog::Associativity::Left);
	_parser.token("<<").symbol("SHIFT_LEFT").description("<<").action([&](std::string_view str) -> Value { return emplace_back(TokenType::SHIFT_LEFT, std::string{str}); })
		.precedence(11, pog::Associativity::Left);
	_parser.token(">>").symbol("SHIFT_RIGHT").description(">>").action([&](std::string_view str) -> Value { return emplace_back(TokenType::SHIFT_RIGHT, std::string{str}); })
		.precedence(11, pog::Associativity::Left);
	_parser.token(R"(-)").symbol("MINUS").description("-").action([&](std::string_view str) -> Value { return emplace_back(TokenType::MINUS, std::string{str}); })
		.precedence(12, pog::Associativity::Left);
	_parser.token(R"(\+)").symbol("PLUS").description("+").action([&](std::string_view str) -> Value { return emplace_back(TokenType::PLUS, std::string{str}); })
		.precedence(12, pog::Associativity::Left);
	_parser.token(R"(\*)").symbol("MULTIPLY").description("*").action([&](std::string_view str) -> Value { return emplace_back(TokenType::MULTIPLY, std::string{str}); })
		.precedence(13, pog::Associativity::Left);
	_parser.token(R"(\\)").symbol("DIVIDE").description("\\").action([&](std::string_view str) -> Value { return emplace_back(TokenType::DIVIDE, std::string{str}); })
		.precedence(13, pog::Associativity::Left);
	_parser.token(R"(\%)").symbol("PERCENT").description("%").action([&](std::string_view str) -> Value { return emplace_back(TokenType::PERCENT, std::string{str}); })
		.precedence(13, pog::Associativity::Left);
	_parser.token(R"(\^)").symbol("BITWISE_XOR").description("^").action([&](std::string_view str) -> Value { return emplace_back(TokenType::BITWISE_XOR, std::string{str}); })
		.precedence(7, pog::Associativity::Left);
	_parser.token(R"(\&)").symbol("BITWISE_AND").description("&").action([&](std::string_view str) -> Value { return emplace_back(TokenType::BITWISE_AND, std::string{str}); })
		.precedence(8, pog::Associativity::Left);
	_parser.token(R"(\|)").symbol("BITWISE_OR").description("|").action([&](std::string_view str) -> Value { return emplace_back(TokenType::BITWISE_OR, std::string{str}); })
		.precedence(6, pog::Associativity::Left);
	_parser.token(R"(\~)").symbol("BITWISE_NOT").description("~").action([&](std::string_view str) -> Value { return emplace_back(TokenType::BITWISE_NOT, std::string{str}); })
		.precedence(14, pog::Associativity::Right);
	_parser.token("\\(").symbol("LP").description("(").action([&](std::string_view str) -> Value { return emplace_back(TokenType::LP, std::string{str}); });
	_parser.token("\\)").symbol("RP").description(")").action([&](std::string_view str) -> Value { return emplace_back(TokenType::RP, std::string{str}); })
		.precedence(1, pog::Associativity::Left);
	_parser.token("\\{").symbol("LCB").description("{").action([&](std::string_view str) -> Value {
		if (sectionStrings())
			enter_state("$hexstr");
		return emplace_back(TokenType::LCB, std::string{str});
	});
	_parser.token("\\}").symbol("RCB").description("}").action([&](std::string_view str) -> Value { return emplace_back(TokenType::RCB, std::string{str}); });
	_parser.token("\\[").symbol("LSQB").description("[").action([&](std::string_view str) -> Value { return emplace_back(TokenType::LSQB, std::string{str}); });
	_parser.token("\\]").symbol("RSQB").description("]").action([&](std::string_view str) -> Value { return emplace_back(TokenType::RSQB, std::string{str}); });
	_parser.token("=").symbol("ASSIGN").description("=").action([&](std::string_view str) -> Value { return emplace_back(TokenType::ASSIGN, std::string{str}); });
	_parser.token(":").symbol("COLON").description(":").action([&](std::string_view str) -> Value { return emplace_back(TokenType::COLON, std::string{str}); });
	_parser.token(",").symbol("COMMA").description(",").action([&](std::string_view str) -> Value { return emplace_back(TokenType::COMMA, std::string{str}); })
		.precedence(1, pog::Associativity::Left);
	_parser.token("/").states("@default").symbol("SLASH").description("/").action([&](std::string_view str) -> Value {
		enter_state("$regexp");
		return std::string{str};
	});
	_parser.token("global").symbol("GLOBAL").description("global").action([&](std::string_view str) -> Value { return emplace_back(TokenType::GLOBAL, std::string{str}); });
	_parser.token("private").symbol("PRIVATE").description("private").action([&](std::string_view str) -> Value { return emplace_back(TokenType::PRIVATE, std::string{str}); });
	_parser.token("rule").symbol("RULE").description("rule").action([&](std::string_view str) -> Value { return emplace_back(TokenType::RULE, std::string{str}); });
	_parser.token("meta").symbol("META").description("meta").action([&](std::string_view str) -> Value { return emplace_back(TokenType::META, std::string{str}); });
	if (_features & Features::AvastOnly)
		_parser.token("variables").symbol("VARIABLES").description("variables").action([&](std::string_view str) -> Value { return emplace_back(TokenType::VARIABLES, std::string{str}); });
	_parser.token("strings").symbol("STRINGS").description("strings").action([&](std::string_view str) -> Value { sectionStrings(true); return emplace_back(TokenType::STRINGS, std::string{str}); });
	_parser.token("condition").symbol("CONDITION").description("condition").action([&](std::string_view str) -> Value { sectionStrings(false); return emplace_back(TokenType::CONDITION, std::string{str}); });
	_parser.token("ascii").symbol("ASCII").description("ascii").action([&](std::string_view str) -> Value { return emplace_back(TokenType::ASCII, std::string{str}); });
	_parser.token("nocase").symbol("NOCASE").description("nocase").action([&](std::string_view str) -> Value { return emplace_back(TokenType::NOCASE, std::string{str}); });
	_parser.token("wide").symbol("WIDE").description("wide").action([&](std::string_view str) -> Value { return emplace_back(TokenType::WIDE, std::string{str}); });
	_parser.token("fullword").symbol("FULLWORD").description("fullword").action([&](std::string_view str) -> Value { return emplace_back(TokenType::FULLWORD, std::string{str}); });
	_parser.token("xor").symbol("XOR").description("xor").action([&](std::string_view str) -> Value { return emplace_back(TokenType::XOR, std::string{str}); });
	_parser.token("base64").symbol("BASE64").description("base64").action([&](std::string_view str) -> Value { return emplace_back(TokenType::BASE64, std::string{str}); });
	_parser.token("base64wide").symbol("BASE64WIDE").description("base64wide").action([&](std::string_view str) -> Value { return emplace_back(TokenType::BASE64WIDE, std::string{str}); });
	_parser.token("true").symbol("BOOL_TRUE").description("true").action([&](std::string_view) -> Value { return emplace_back(TokenType::BOOL_TRUE, true); });
	_parser.token("false").symbol("BOOL_FALSE").description("false").action([&](std::string_view) -> Value { return emplace_back(TokenType::BOOL_FALSE, false); });
	_parser.token("import").symbol("IMPORT_KEYWORD").description("import").action([&](std::string_view str) -> Value { return emplace_back(TokenType::IMPORT_KEYWORD, std::string{str}); });
	_parser.token("not").symbol("NOT").description("not").action([&](std::string_view str) -> Value { return emplace_back(TokenType::NOT, std::string{str}); })
		.precedence(14, pog::Associativity::Right);
	if (_features & Features::AvastOnly) {
		_parser.token("defined").symbol("DEFINED").description("defined").action(
						[&](std::string_view str) -> Value {
							return emplace_back(TokenType::DEFINED, std::string{str});
						})
				.precedence(15, pog::Associativity::Right);
	}
	_parser.token("and").symbol("AND").description("and").action([&](std::string_view str) -> Value { return emplace_back(TokenType::AND, std::string{str}); })
		.precedence(5, pog::Associativity::Left);
	_parser.token("or").symbol("OR").description("or").action([&](std::string_view str) -> Value { return emplace_back(TokenType::OR, std::string{str}); })
		.precedence(4, pog::Associativity::Left);
	_parser.token("all").symbol("ALL").description("all").action([&](std::string_view str) -> Value { return emplace_back(TokenType::ALL, std::string{str}); });
	_parser.token("any").symbol("ANY").description("any").action([&](std::string_view str) -> Value { return emplace_back(TokenType::ANY, std::string{str}); });
	_parser.token("none").symbol("NONE").description("none").action([&](std::string_view str) -> Value { return emplace_back(TokenType::NONE, std::string{str}); });
	_parser.token("of").symbol("OF").description("of").action([&](std::string_view str) -> Value { return emplace_back(TokenType::OF, std::string{str}); });
	_parser.token("them").symbol("THEM").description("them").action([&](std::string_view str) -> Value { return emplace_back(TokenType::THEM, std::string{str}); });
	_parser.token("for").symbol("FOR").description("for").action([&](std::string_view str) -> Value { return emplace_back(TokenType::FOR, std::string{str}); });
	_parser.token("entrypoint").symbol("ENTRYPOINT").description("entrypoint").action([&](std::string_view str) -> Value { return emplace_back(TokenType::ENTRYPOINT, std::string{str}); });
	_parser.token("at").symbol("AT").description("at").action([&](std::string_view str) -> Value { return emplace_back(TokenType::OP_AT, std::string{str}); });
	_parser.token("in").symbol("IN").description("in").action([&](std::string_view str) -> Value { return emplace_back(TokenType::OP_IN, std::string{str}); });
	_parser.token("filesize").symbol("FILESIZE").description("filesize").action([&](std::string_view str) -> Value { return emplace_back(TokenType::FILESIZE, std::string{str}); });
	_parser.token("contains").symbol("CONTAINS").description("contains").action([&](std::string_view str) -> Value { return emplace_back(TokenType::CONTAINS, std::string{str}); });
	_parser.token("matches").symbol("MATCHES").description("matches").action([&](std::string_view str) -> Value { return emplace_back(TokenType::MATCHES, std::string{str}); });
	_parser.token("iequals").symbol("IEQUALS").description("iequals").action([&](std::string_view str) -> Value { return emplace_back(TokenType::IEQUALS, std::string{str}); });

	// $include
	_parser.token("include").symbol("INCLUDE_DIRECTIVE").description("include").enter_state("$include").action([&](std::string_view str) -> Value {
		return emplace_back(TokenType::INCLUDE_DIRECTIVE, std::string{str});
	});
	_parser.token("\r\n|\n").states("$include").action([&](std::string_view str) -> Value {
		currentFileContext()->getLocation().addLine();
		currentFileContext()->getTokenStream()->setNewLineChar(std::string{str});
		return emplace_back(TokenType::NEW_LINE, std::string{str});
	});
	_parser.token(R"([ \v\t])").states("$include");
	_parser.token(R"(\")").states("$include").enter_state("$include_file");
	//$include_file
	_parser.token(R"([^"]+\")").symbol("INCLUDE_FILE").description("include path").states("$include_file").enter_state("@default").action([&](std::string_view str) -> Value {
		auto filePath = std::string{str}.substr(0, str.size()-1);
		TokenIt includeToken = emplace_back(TokenType::INCLUDE_PATH, filePath);
		const auto& ts = includeToken->initializeSubTokenStream();
		if (!includeFile(filePath, ts))
		{
			if (!incompleteMode())
				error_handle(currentFileContext()->getLocation(), "Unable to include file '" + filePath + "'");
		}

		return includeToken;
	});
	//$include_file end

	_parser.token(R"(0x[0-9a-fA-F]+)").symbol("INTEGER").description("integer").action([&](std::string_view str) -> Value {
		int64_t n = 0;
		strToNum(std::string{str}, n, std::hex);
		return emplace_back(TokenType::INTEGER, n, std::make_optional(std::string{str}));
	});
	_parser.token(R"([0-9]+KB)").symbol("INTEGER").description("integer").action([&](std::string_view str) -> Value {
		int64_t n = 0;
		strToNum(std::string{str}.substr(0, str.size()-2), n);
		return emplace_back(TokenType::INTEGER, 1000 * n, std::make_optional(std::string{str}));
	});
	_parser.token(R"([0-9]+MB)").symbol("INTEGER").description("integer").action([&](std::string_view str) -> Value {
		int64_t n = 0;
		strToNum(std::string{str}.substr(0, str.size()-2), n);
		return emplace_back(TokenType::INTEGER, 1000000 * n, std::make_optional(std::string{str}));
	});
	_parser.token(R"([0-9]+)").symbol("INTEGER").description("integer").action([&](std::string_view str) -> Value {
		int64_t n = 0;
		strToNum(std::string{str}, n);
		return emplace_back(TokenType::INTEGER, n, std::make_optional(std::string{str}));
	});

	_parser.token(R"(\/\/[^\n]*)").states("@default", "$hexstr", "@hexstr_jump").action([&](std::string_view str) -> Value {
		auto it = emplace_back(TokenType::ONELINE_COMMENT, std::string{str}, _indent);
		addComment(it);
		return {};
	});
	// $multiline_comment
	// Comment tokens are not delegated with return Value but stored in _comment
	_parser.token(R"(/\*)").states("@default").enter_state("$multiline_comment").action([&](std::string_view str) -> Value {
		_comment.append(std::string{str});
		return {};
	});
	_parser.token(R"(\*/)").states("$multiline_comment").enter_state("@default").action([&](std::string_view str) -> Value {
		_comment.append(std::string{str});
		auto it = emplace_back(TokenType::COMMENT, _comment, _indent);
		addComment(it);
		_indent.clear();
		_comment.clear();
		return {};
	});
	_parser.token(R"(\n)").states("$multiline_comment").action([&](std::string_view str) -> Value {
		currentFileContext()->getLocation().addLine();
		_comment.append(std::string{str});
		return {};
	});
	_parser.token(R"([^\n*]*)").states("$multiline_comment").action([&](std::string_view str) -> Value {
		_comment.append(std::string{str});
		return {};
	});
	_parser.token(R"(\*)").states("$multiline_comment").action([&](std::string_view str) -> Value {
		_comment.append(std::string{str});
		return {};
	});
	// $multiline_comment end

	// $str
	// $str tokens are not delegated with return Value but stored in _strLiteral
	_parser.token(R"(\")").states("@default").enter_state("$str").action([&](std::string_view) -> Value {
		_strLiteral.clear();
		_positionBegin = currentFileContext()->getLocation().begin();
		_escapedContent = false;
		return {};
	});

	_parser.token(R"(\\x[0-9a-fA-F]{2})").states("$str").action([&](std::string_view str) -> Value {
		_strLiteral += "\\x";
		_strLiteral += std::string{str}.substr(2);
		_escapedContent = true;
		return {};
	});
	_parser.token(R"(\\[trn\"\\])").states("$str").action([&](std::string_view str) -> Value { _strLiteral += std::string{str}; return {}; }); //  '\n',  '\t', '\r'
	_parser.token(R"(\\[^\"trnx\\])").states("$str").action([&](std::string_view str) -> Value { error_handle(currentFileContext()->getLocation(), "Syntax error: Unknown escaped sequence '" + std::string{str} + "'"); return {}; });
	_parser.token(R"(([^\\"])+)").states("$str").action([&](std::string_view str) -> Value { _strLiteral += std::string{str}; return {}; });
	_parser.token(R"(\")").states("$str").symbol("STRING_LITERAL").description("\"").enter_state("@default").action([&](std::string_view) -> Value {
		currentFileContext()->getLocation().setBegin(_positionBegin);
		auto strIt = emplace_back(TokenType::STRING_LITERAL, _strLiteral);
		if (_escapedContent)
			strIt->markEscaped();
		return strIt;
	});

	// $str end

	_parser.token("u?int(8|16|32)(be)?").symbol("INTEGER_FUNCTION").description("fixed-width integer function").action([&](std::string_view str) -> Value { return emplace_back(TokenType::INTEGER_FUNCTION, std::string{str}); });
	_parser.token(R"(\$[0-9a-zA-Z_]*)").symbol("STRING_ID").description("string identifier").action([&](std::string_view str) -> Value { return emplace_back(TokenType::STRING_ID, std::string{str}); });

	_parser.token(R"(\$[0-9a-zA-Z_]*\*)").symbol("STRING_ID_WILDCARD").description("string wildcard").action([&](std::string_view str) -> Value { return emplace_back(TokenType::STRING_ID_WILDCARD, std::string{str}); });
	_parser.token(R"(\#[0-9a-zA-Z_]*)").symbol("STRING_COUNT").description("string count").action([&](std::string_view str) -> Value { return emplace_back(TokenType::STRING_COUNT, std::string{str}); });
	_parser.token(R"(\@[0-9a-zA-Z_]*)").symbol("STRING_OFFSET").description("string offset").action([&](std::string_view str) -> Value { return emplace_back(TokenType::STRING_OFFSET, std::string{str}); });
	_parser.token(R"(\![0-9a-zA-Z_]*)").symbol("STRING_LENGTH").description("string length").action([&](std::string_view str) -> Value { return emplace_back(TokenType::STRING_LENGTH, std::string{str}); });
	_parser.token("[a-zA-Z_][0-9a-zA-Z_]*").symbol("ID").description("identifier").action([&](std::string_view str) -> Value { return emplace_back(TokenType::ID, std::string{str}); });

	_parser.token(R"([0-9]+\.[0-9]+)").symbol("DOUBLE").description("float").action([&](std::string_view str) -> Value { return emplace_back(TokenType::DOUBLE, std::stod(std::string(str))); });

	// $hexstr
	_parser.token(R"(\|)").states("$hexstr").symbol("HEX_OR").description("hex string |").action([&](std::string_view str) -> Value { return emplace_back(TokenType::HEX_ALT, std::string{str}); });
	_parser.token(R"(\()").states("$hexstr").symbol("LP").description("hex string (").action([&](std::string_view str) -> Value { return emplace_back(TokenType::LP, std::string{str}); });
	_parser.token(R"(\))").states("$hexstr").symbol("RP").description("hex string )").action([&](std::string_view str) -> Value { return emplace_back(TokenType::RP, std::string{str}); });
	_parser.token(R"(\?)").states("$hexstr").symbol("HEX_WILDCARD").description("hex string ?").action([&](std::string_view str) -> Value { return emplace_back(TokenType::HEX_WILDCARD, std::string{str}); });
	_parser.token(R"(\})").states("$hexstr").enter_state("@default").symbol("RCB").description("}").action([&](std::string_view) -> Value { return emplace_back(TokenType::RCB, "}"); });
	_parser.token("[0-9a-fA-F]").states("$hexstr").symbol("HEX_NIBBLE").description("hex string nibble").action([&](std::string_view str) -> Value {
		std::uint8_t digit = ('A' <= std::toupper(str[0]) && std::toupper(str[0]) <= 'F') ? std::toupper(str[0]) - 'A' + 10 : str[0] - '0';
		return emplace_back(TokenType::HEX_NIBBLE, static_cast<std::uint64_t>(digit), std::string{str});
	});
	_parser.token(R"(\[)").states("$hexstr").enter_state("$hexstr_jump").symbol("LSQB").description("hex string [").action([&](std::string_view str) -> Value { return emplace_back(TokenType::HEX_JUMP_LEFT_BRACKET, std::string{str}); });
	_parser.token("[0-9]*").states("$hexstr_jump").symbol("HEX_INTEGER").description("hex string integer").action([&](std::string_view str) -> Value {
		std::string numStr = std::string{str};
		std::uint64_t num = 0;
		strToNum(numStr, num, std::dec);
		return emplace_back(TokenType::INTEGER, num, numStr);
	});
	_parser.token(R"(\-)").states("$hexstr_jump").symbol("DASH").description("hex string -").action([&](std::string_view str) -> Value { return emplace_back(TokenType::DASH, std::string{str}); });
	_parser.token(R"(\])").states("$hexstr_jump").symbol("RSQB").description("hex string ]").enter_state("$hexstr").action([&](std::string_view str) -> Value { return emplace_back(TokenType::HEX_JUMP_RIGHT_BRACKET, std::string{str}); });

	// tokens are not delegated with return Value but created in grammar rules actions
	_parser.token(R"(//[^\n]*)").states("$hexstr_jump").action([](std::string_view str) -> Value { return std::string{str}; });
	// $hexstr multiline comment
	_parser.token(R"(/\*)").states("$hexstr").enter_state("$hexstr_multiline_comment").action([&](std::string_view str) -> Value {
		_comment.append(std::string{str});
		return {};
	});
	_parser.token(R"(\*/)").states("$hexstr_multiline_comment").enter_state("$hexstr").action([&](std::string_view str) -> Value {
		_comment.append(std::string{str});
		auto it = emplace_back(TokenType::COMMENT, _comment, _indent);
		addComment(it);
		_indent.clear();
		_comment.clear();
		return {};
	});
	_parser.token(R"(\n)").states("$hexstr_multiline_comment").action([&](std::string_view str) -> Value {
		currentFileContext()->getLocation().addLine();
		_comment.append(std::string{str});
		return {};
	});
	_parser.token(R"(.)").states("$hexstr_multiline_comment").action([&](std::string_view str) -> Value {
		_comment.append(std::string{str});
		return {};
	});
	// $hexstr multiline comment end

	_parser.token(R"({[ \v\t]}*)").states("$hexstr", "@hexstr_jump").action([](std::string_view) -> Value { return {}; });;
	_parser.token(R"([\n])").states("$hexstr", "@hexstr_jump").action([&](std::string_view) -> Value {
		currentFileContext()->getLocation().addLine();
		_indent.clear();
		return emplace_back(TokenType::NEW_LINE, currentFileContext()->getTokenStream()->getNewLineStyle());
	});
	_parser.token(R"(\s)").states("$hexstr", "@hexstr_jump");
	// $hexstr end

	// $regexp
	// $regexp tokens are delegated as strings and then emplaced to TokenStream in grammar rules actions
	_parser.token(R"(/i?s?)").states("$regexp").enter_state("@default").symbol("SLASH").description("/").action([](std::string_view str) -> Value {
		return std::string{str};
	});
	_parser.token(R"(\()").states("$regexp").symbol("LP").description("(").action([](std::string_view str) -> Value { return std::string{str}; });
	_parser.token(R"(\))").states("$regexp").symbol("RP").description(")").action([](std::string_view str) -> Value { return std::string{str}; });
	_parser.token(R"(\|)").states("$regexp").symbol("REGEXP_OR").description("regexp |").action([](std::string_view str) -> Value { return std::string{str}; });
	_parser.token(R"(\*)").states("$regexp").symbol("REGEXP_ITER").description("regexp *").action([](std::string_view str) -> Value { return std::string{str}; });
	_parser.token(R"(\+)").states("$regexp").symbol("REGEXP_PITER").description("regexp +").action([](std::string_view str) -> Value { return std::string{str}; });
	_parser.token(R"(\?)").states("$regexp").symbol("REGEXP_OPTIONAL").description("regexp ?").action([](std::string_view str) -> Value { return std::string{str}; });
	_parser.token(R"(\^)").states("$regexp").symbol("REGEXP_START_OF_LINE").description("regexp ^").action([](std::string_view str) -> Value { return std::string{str}; });
	_parser.token(R"(\$)").states("$regexp").symbol("REGEXP_END_OF_LINE").description("regexp $").action([](std::string_view str) -> Value { return std::string{str}; });
	_parser.token(R"(\.)").states("$regexp").symbol("REGEXP_ANY_CHAR").description("regexp .").action([](std::string_view str) -> Value { return std::string{str}; });
	_parser.token(R"(\{[0-9]*,[0-9]*\})").states("$regexp").symbol("REGEXP_RANGE").description("regexp range").action([&](std::string_view str) -> Value {
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
	_parser.token(R"({[0-9]+})").states("$regexp").symbol("REGEXP_RANGE").description("regexp range").action([&](std::string_view str) -> Value {
		std::string numStr = std::string(str.substr(1, str.size()-2));

		std::optional<std::uint64_t> range;
		std::uint64_t num = 0;
		if (strToNum(numStr, num, std::dec))
			range = num;

		return std::make_pair(range, range);
	});
	_parser.token(R"(\\x[a-zA-Z0-9]{2})").states("$regexp").symbol("REGEXP_ESCAPE").description("regexp escaped character").action([](std::string_view str) -> Value {
		return std::string{str};
	});
	_parser.token(R"([^\\\[\(\)\|\$\.\^\+\+*\?])").states("$regexp").symbol("REGEXP_CHAR").description("regexp character").action([](std::string_view str) -> Value {
		return std::string{str};
	});
	_parser.token(R"(\\w)").states("$regexp").symbol("REGEXP_WORD_CHAR").description("regexp \\w").action([](std::string_view) -> Value { return {};});
	_parser.token(R"(\\W)").states("$regexp").symbol("REGEXP_NON_WORD_CHAR").description("regexp \\W").action([](std::string_view) -> Value { return {};});
	_parser.token(R"(\\s)").states("$regexp").symbol("REGEXP_SPACE").description("regexp \\s").action([](std::string_view) -> Value { return {};});
	_parser.token(R"(\\S)").states("$regexp").symbol("REGEXP_NON_SPACE").description("regexp \\S").action([](std::string_view) -> Value { return {};});
	_parser.token(R"(\\d)").states("$regexp").symbol("REGEXP_DIGIT").description("regexp \\d").action([](std::string_view) -> Value { return {};});
	_parser.token(R"(\\D)").states("$regexp").symbol("REGEXP_NON_DIGIT").description("regexp \\D").action([](std::string_view) -> Value { return {};});
	_parser.token(R"(\\b)").states("$regexp").symbol("REGEXP_WORD_BOUNDARY").description("regexp \\b").action([](std::string_view) -> Value { return {};});
	_parser.token(R"(\\B)").states("$regexp").symbol("REGEXP_NON_WORD_BOUNDARY").description("regexp \\B").action([](std::string_view) -> Value { return {};});
	_parser.token(R"(\\.)").states("$regexp").symbol("REGEXP_CHAR").description("regexp .").action([](std::string_view str) -> Value {
		return std::string{str};
	});
	_parser.token(R"(\[\^\])").states("$regexp").enter_state("$regexp_class").action([&](std::string_view) -> Value { _regexpClass = "^]"; return {}; });
	_parser.token(R"(\[\])").states("$regexp").enter_state("$regexp_class").action([&](std::string_view) -> Value {	_regexpClass = "]"; return {}; });
	_parser.token(R"(\[\^)").states("$regexp").enter_state("$regexp_class").action([&](std::string_view) -> Value {	_regexpClass = "^"; return {}; });
	_parser.token(R"(\[)").states("$regexp").enter_state("$regexp_class").action([&](std::string_view) -> Value {
		_regexpClass.clear();
		return {};
}	);
	_parser.token(R"(\])").states("$regexp_class").symbol("REGEXP_CLASS").description("regexp class").enter_state("$regexp").action([&](std::string_view) -> Value {
		return std::make_pair(true, _regexpClass);
	});
	_parser.token(R"(\\w)").states("$regexp_class").action([&](std::string_view) -> Value { _regexpClass += "\\w"; return {};});
	_parser.token(R"(\\W)").states("$regexp_class").action([&](std::string_view) -> Value { _regexpClass += "\\W"; return {};});
	_parser.token(R"(\\s)").states("$regexp_class").action([&](std::string_view) -> Value { _regexpClass += "\\s"; return {};});
	_parser.token(R"(\\S)").states("$regexp_class").action([&](std::string_view) -> Value { _regexpClass += "\\S"; return {};});
	_parser.token(R"(\\d)").states("$regexp_class").action([&](std::string_view) -> Value { _regexpClass += "\\d"; return {};});
	_parser.token(R"(\\D)").states("$regexp_class").action([&](std::string_view) -> Value { _regexpClass += "\\D"; return {};});
	_parser.token(R"(\\b)").states("$regexp_class").action([&](std::string_view) -> Value { _regexpClass += "\\b"; return {};});
	_parser.token(R"(\\B)").states("$regexp_class").action([&](std::string_view) -> Value { _regexpClass += "\\B"; return {};});
	_parser.token(R"(\\\\)").states("$regexp_class").action([&](std::string_view) -> Value { _regexpClass += "\\\\"; return {};});
	_parser.token(R"(\\\])").states("$regexp_class").action([&](std::string_view) -> Value { _regexpClass += "\\]"; return {};});
	_parser.token(R"(\\\[)").states("$regexp_class").action([&](std::string_view) -> Value { _regexpClass += "\\["; return {};});
	_parser.token(R"(\[)").states("$regexp_class").action([&](std::string_view) -> Value { _regexpClass += "["; return {}; });
	_parser.token(R"([^\]\[])").states("$regexp_class").action([&](std::string_view str) -> Value { _regexpClass += std::string{str}[0]; return {}; });
	// $regexp end

	_parser.end_token().states("@default", "$str", "$include", "$hexstr", "hexstr_jump", "$regexp", "$regexp_class").action([&](std::string_view) -> Value {
		_errorLocation = currentFileContext()->getLocation();
		includeEnd();
		return {};
	});
}

void ParserDriver::defineGrammar()
{
	_parser.rule("rules")
		.production("rules", "rule")
		.production("rules", "import")
		.production("rules", "include")
		.production()
		;

	_parser.rule("import") // {}
		.production("IMPORT_KEYWORD", "STRING_LITERAL", [&](auto&& args) -> Value {
			TokenIt import = args[1].getTokenIt();
			import->setType(TokenType::IMPORT_MODULE);
			if (!_file.addImport(import, *_modules))
			{
				if (!incompleteMode())
					error_handle(import->getLocation(), "Unrecognized module '" + import->getString() + "' imported");
			}
			return {};
		})
		;

	_parser.rule("include") // {}
		.production("INCLUDE_DIRECTIVE", "INCLUDE_FILE", [&](auto&&) -> Value {
			return {};
		})
		;

	auto const common_last_rule = [&](auto&&) -> Value {
		_lastRuleLocation = currentFileContext()->getLocation();
		_lastRuleTokenStream = currentFileContext()->getTokenStream();
		return {};
	};

	auto const common_rule_init = [&](auto&& args) -> Value {
		const std::string& name_text = args[3].getTokenIt()->getString();
		if (ruleExists(name_text))
			error_handle(args[3].getTokenIt()->getLocation(), "Redefinition of rule '" + args[3].getTokenIt()->getString() + "'");
		args[3].getTokenIt()->setType(TokenType::RULE_NAME);
		args[3].getTokenIt()->setValue(std::make_shared<ValueSymbol>(name_text, Expression::Type::Bool));
		return {};
	};

	if (_features & Features::AvastOnly)
	{
		_parser.rule("sections_summary") // std::shared_ptr<SectionsSummary>
				.production("sections_summary", "variables", [&](auto&& args) -> Value {
					auto section_summary = std::move(args[0].getSectionsSummary());
					if (section_summary->isVariablesSet())
					{
						error_handle(currentFileContext()->getLocation(), "Duplicate variables section.");
					}
					section_summary->setVariables(args[1].getVariables());
					return section_summary;
				})
				.production("sections_summary", "strings", [&](auto&& args) -> Value {
					auto section_summary = std::move(args[0].getSectionsSummary());
					if (section_summary->isStringsTrieSet())
					{
						error_handle(currentFileContext()->getLocation(), "Duplicate strings section.");
					}
					section_summary->setStringsTrie(std::move(args[1].getStringsTrie()));
					return section_summary;
				})
				.production([&](auto&&) -> Value {
					auto variables = std::vector<Variable>();
					auto strings = std::make_shared<Rule::StringsTrie>();
					setCurrentStrings(strings);
					
					return std::make_shared<SectionsSummary>(strings, variables);
				})
				;

		_parser.rule("rule") // {}
			.production(
				"rule_mods", "RULE", common_last_rule, "ID", common_rule_init, "tags", "LCB", "metas", "sections_summary", "condition" , "RCB", [&](auto&& args) -> Value {
				auto rule = createCommonRule(args);
				auto sections_summary = std::move(args[8].getSectionsSummary());
				auto variables = sections_summary->getVariables();

				rule.setVariables(variables);
				rule.setStringsTrie(std::move(sections_summary->getStringsTrie()));
				rule.setCondition(std::move(args[9].getExpression()));
				args[10].getTokenIt()->setType(TokenType::RULE_END);

				for(auto iter = variables.begin(); iter != variables.end(); iter++) {
					removeLocalSymbol(iter->getKey());
				}

				addRule(std::move(rule));
				return {};
			})
			;
	}
	else
	{
		_parser.rule("strings_optional")
			.production("strings", [&](auto&& args) -> Value {
				return std::move(args[0].getStringsTrie());
			})
			.production([&](auto&&) -> Value {
				auto strings = std::make_shared<Rule::StringsTrie>();
				setCurrentStrings(strings);
				return strings;
			})
			;

		_parser.rule("rule") // {}
			.production(
				"rule_mods", "RULE", common_last_rule, "ID", common_rule_init, "tags", "LCB", "metas", "strings_optional", "condition" , "RCB", [&](auto&& args) -> Value {
				auto rule = createCommonRule(args);
				rule.setStringsTrie(std::move(args[8].getStringsTrie()));
				rule.setCondition(std::move(args[9].getExpression()));
				args[10].getTokenIt()->setType(TokenType::RULE_END);

				addRule(std::move(rule));
				return {};
			})
			;
	}

	_parser.rule("rule_mods") // vector<TokenIt>
		.production("rule_mods", "PRIVATE", [](auto&& args) -> Value {
			std::vector<TokenIt> mods = std::move(args[0].getMultipleTokenIt());
			TokenIt mod = args[1].getTokenIt();
			mod->setType(TokenType::PRIVATE);
			mods.emplace_back(std::move(mod));
			return mods;
		})
		.production("rule_mods", "GLOBAL", [](auto&& args) -> Value {
			std::vector<TokenIt> mods = std::move(args[0].getMultipleTokenIt());
			TokenIt mod = args[1].getTokenIt();
			mod->setType(TokenType::GLOBAL);
			mods.emplace_back(std::move(mod));
			return mods;
		})
		.production([](auto&&) -> Value { return std::vector<TokenIt>(); })
		;

	_parser.rule("tags") // vector<TokenIt>
		.production("COLON", "tag_list", [](auto&& args) -> Value {	return std::move(args[1]); })
		.production([](auto&&) -> Value { return std::vector<TokenIt>(); })
		;

	_parser.rule("tag_list") // vector<TokenIt>
		.production("tag_list", "ID", [](auto&& args) -> Value {
			std::vector<TokenIt> tags = std::move(args[0].getMultipleTokenIt());
			TokenIt tag = args[1].getTokenIt();
			tag->setType(TokenType::TAG);
			tags.emplace_back(std::move(tag));
			return tags;
		})
		.production("ID", [](auto&& args) -> Value {
			std::vector<TokenIt> tags;
			TokenIt tag = args[0].getTokenIt();
			tag->setType(TokenType::TAG);
			tags.emplace_back(std::move(tag));
			return tags;
		})
		;

	_parser.rule("metas") // vector<Meta>
		.production("META", "COLON", "metas_body", [](auto&& args) -> Value {
			args[1].getTokenIt()->setType(TokenType::COLON_BEFORE_NEWLINE);
			return std::move(args[2]);
		})
		.production([](auto&&) -> Value { return std::vector<yaramod::Meta>(); })
		;

	_parser.rule("metas_body") // vector<Meta>
		.production("metas_body", "ID", "ASSIGN", "literal", [](auto&& args) -> Value {
			std::vector<Meta> body = std::move(args[0].getMetas());
			TokenIt key = args[1].getTokenIt();
			key->setType(TokenType::META_KEY);
			TokenIt val = args[3].getTokenIt();
			val->setType(TokenType::META_VALUE);
			body.emplace_back(key, val);
			return body;
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

	if (_features & Features::AvastOnly)
	{
		_parser.rule("variables") // vector<Variable>
			.production("VARIABLES", "COLON", "variables_body", [this](auto&& args) -> Value {
				args[1].getTokenIt()->setType(TokenType::COLON_BEFORE_NEWLINE);
				return std::move(args[2]);
			})
			;

		_parser.rule("variables_body") // vector<Variable>
			.production("variables_body", "ID", "ASSIGN", "expression", [&](auto&& args) -> Value {
				std::vector<Variable> body = std::move(args[0].getVariables());
				TokenIt key = args[1].getTokenIt();
				key->setType(TokenType::VARIABLE_KEY);
				auto expr = args[3].getExpression();

				std::shared_ptr<Symbol> symbol;
				if (expr->isObject())
					symbol = std::make_shared<ReferenceSymbol>(key->getString(), std::static_pointer_cast<const IdExpression>(expr)->getSymbol());
				else
					symbol = std::make_shared<ValueSymbol>(key->getString(), expr->getType());

				if (!addLocalSymbol(symbol))
				{
					error_handle(currentFileContext()->getLocation(), "Redefinition of identifier " + key->getString());
				}

				body.emplace_back(key, expr);
				return body;
			})
			.production([](auto&&) -> Value { return std::vector<Variable>(); })
			;
	}

	_parser.rule("strings") // shared_ptr<StringsTrie>
		.production("STRINGS", "COLON", "strings_body_nonempty", [](auto&& args) -> Value {
			args[1].getTokenIt()->setType(TokenType::COLON_BEFORE_NEWLINE);
			return std::move(args[2]);
		})
		;

	_parser.rule("strings_body_nonempty") // shared_ptr<StringsTrie>
		.production(
			"strings_body", "STRING_ID", "ASSIGN", [](auto&& args) -> Value {
				args[1].getTokenIt()->setType(TokenType::STRING_ID_AFTER_NEWLINE);
				return {};
			},
			"string", [&](auto&& args) -> Value {
				const std::string& id = args[1].getTokenIt()->getPureText();
				const std::string& trieId = isAnonymousStringId(id) ? generateAnonymousStringPseudoId() : id;
				auto string = std::move(args[4].getYaramodString());
				string->setIdentifier(args[1].getTokenIt(), args[2].getTokenIt());
				auto strings = std::move(args[0].getStringsTrie());
				if (!strings->insert(trieId, std::move(string)))
				{
					error_handle(args[1].getTokenIt()->getLocation(), "Redefinition of string '" + trieId + "'");
				}
				return strings;
			}
		)
		;

	_parser.rule("strings_body") // shared_ptr<StringsTrie>
		.production("strings_body_nonempty", [&](auto&& args) -> Value {
			return std::move(args[0].getStringsTrie());
		})
		.production([&](auto&&) -> Value {
			auto strings = std::make_shared<Rule::StringsTrie>();
			setCurrentStrings(strings);
			return strings;
		})
		;

	_parser.rule("string")
		.production("STRING_LITERAL", "plain_string_mods", [&](auto&& args) -> Value {
			auto string = std::make_shared<PlainString>(currentFileContext()->getTokenStream(), std::move(args[0].getTokenIt()));
			auto mods = std::move(args[1].getStringMods());
			string->setModifiers(std::move(mods));
			return string;
		})
		.production("LCB", [](auto&& args) -> Value {
				args[0].getTokenIt()->setType(TokenType::HEX_START_BRACKET);
				return {};
			},
			"hex_string", "RCB", "hex_string_mods", [&](auto&& args) -> Value {
				args[3].getTokenIt()->setType(TokenType::HEX_END_BRACKET);
				auto hexString = std::make_shared<HexString>(currentFileContext()->getTokenStream(), args[0].getTokenIt(), std::move(args[2].getMultipleHexUnits()), args[3].getTokenIt());
				hexString->setModifiers(std::move(args[4].getStringMods()));
				return hexString;
			}
		)
		.production("regexp", "regexp_mods", [](auto&& args) -> Value {
			auto regexp_string = std::move(args[0].getYaramodString());
			auto mods = std::move(args[1].getStringMods());
			regexp_string->setModifiers(std::move(mods));
			return regexp_string;
		})
		;

	_parser.rule("plain_string_mods") // std::vector<std::shared_ptr<StringModifier>>
		.production("plain_string_mods", "plain_string_mod", [&](auto&& args) -> Value {
			auto stringMods = std::move(args[0].getStringMods());
			auto stringMod = std::move(args[1].getStringMod());
			checkStringModifier(stringMods, stringMod);
			stringMods.push_back(stringMod);
			return stringMods;
		})
		.production([](auto&&) -> Value {
			return StringModifiers{};
		})
		;

	_parser.rule("regexp_mods") // std::vector<std::shared_ptr<StringModifier>>
		.production("regexp_mods", "regexp_mod", [&](auto&& args) -> Value {
			auto stringMods = std::move(args[0].getStringMods());
			auto stringMod = std::move(args[1].getStringMod());
			checkStringModifier(stringMods, stringMod);
			stringMods.push_back(stringMod);
			return stringMods;
		})
		.production([](auto&&) -> Value {
			return StringModifiers{};
		})
		;

	_parser.rule("hex_string_mods") // std::vector<std::shared_ptr<StringModifier>>
		.production("hex_string_mods", "hex_string_mod", [&](auto&& args) -> Value {
			auto stringMods = std::move(args[0].getStringMods());
			auto stringMod = std::move(args[1].getStringMod());
			checkStringModifier(stringMods, stringMod);
			stringMods.push_back(stringMod);
			return stringMods;
		})
		.production([](auto&&) -> Value {
			return StringModifiers{};
		})
		;

	_parser.rule("plain_string_mod") // std::shared_ptr<StringModifier>
		.production("XOR", [](auto&& args) -> Value {
			return std::make_shared<XorStringModifier>(args[0].getTokenIt());
		})
		.production("XOR", "LP", "INTEGER", "RP", [](auto&& args) -> Value {
			auto key = args[2].getTokenIt()->getUInt();
			return std::make_shared<XorStringModifier>(args[0].getTokenIt(), args[3].getTokenIt(), static_cast<std::uint32_t>(key));
		})
		.production("XOR", "LP", "INTEGER", "MINUS", "INTEGER", "RP", [](auto&& args) -> Value {
			auto low = args[2].getTokenIt()->getUInt();
			auto high = args[4].getTokenIt()->getUInt();
			return std::make_shared<XorStringModifier>(args[0].getTokenIt(), args[5].getTokenIt(), static_cast<std::uint32_t>(low), static_cast<std::uint32_t>(high));
		})
		.production("BASE64", [](auto&& args) -> Value {
			return std::make_shared<Base64StringModifier>(args[0].getTokenIt());
		})
		.production("BASE64", "LP", "STRING_LITERAL", "RP", [](auto&& args) -> Value {
			auto alphabet = unescapeString(args[2].getTokenIt()->getString());
			return std::make_shared<Base64StringModifier>(args[0].getTokenIt(), args[3].getTokenIt(), alphabet);
		})
		.production("BASE64WIDE", [](auto&& args) -> Value {
			return std::make_shared<Base64WideStringModifier>(args[0].getTokenIt());
		})
		.production("BASE64WIDE", "LP", "STRING_LITERAL", "RP", [](auto&& args) -> Value {
			auto alphabet = unescapeString(args[2].getTokenIt()->getString());
			return std::make_shared<Base64WideStringModifier>(args[0].getTokenIt(), args[3].getTokenIt(), alphabet);
		})
		.production("regexp_mod", [](auto&& args) -> Value {
			return std::move(args[0]);
		})
		;

	_parser.rule("regexp_mod") // std::shared_ptr<StringModifier>
		.production("ASCII", [](auto&& args) -> Value {
			return std::make_shared<AsciiStringModifier>(args[0].getTokenIt());
		})
		.production("WIDE", [](auto&& args) -> Value {
			return std::make_shared<WideStringModifier>(args[0].getTokenIt());
		})
		.production("NOCASE", [](auto&& args) -> Value {
			return std::make_shared<NocaseStringModifier>(args[0].getTokenIt());
		})
		.production("FULLWORD", [](auto&& args) -> Value {
			return std::make_shared<FullwordStringModifier>(args[0].getTokenIt());
		})
		.production("hex_string_mod", [](auto&& args) -> Value {
			return std::move(args[0]);
		})
		;

	_parser.rule("hex_string_mod") // std::shared_ptr<StringModifier>
		.production("PRIVATE", [](auto&& args) -> Value {
			args[0].getTokenIt()->setType(TokenType::PRIVATE_STRING_MODIFIER);
			return std::make_shared<PrivateStringModifier>(args[0].getTokenIt());
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
			return units;
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
			return output;
		})
		.production("HEX_NIBBLE", "HEX_WILDCARD", [](auto&& args) -> Value {
			std::vector<std::shared_ptr<HexStringUnit>> output;
			auto first = std::make_shared<HexStringNibble>(args[0].getTokenIt());
			args[1].getTokenIt()->setType(TokenType::HEX_WILDCARD_HIGH);
			auto second = std::make_shared<HexStringWildcard>(args[1].getTokenIt());
			output.reserve(2);
			output.push_back(std::move(first));
			output.push_back(std::move(second));
			return output;
		})
		.production("HEX_WILDCARD", "HEX_NIBBLE", [](auto&& args) -> Value {
			std::vector<std::shared_ptr<HexStringUnit>> output;
			args[0].getTokenIt()->setType(TokenType::HEX_WILDCARD_LOW);
			auto first = std::make_shared<HexStringWildcard>(args[0].getTokenIt());
			auto second = std::make_shared<HexStringNibble>(args[1].getTokenIt());
			output.reserve(2);
			output.push_back(std::move(first));
			output.push_back(std::move(second));
			return output;
		})
		.production("HEX_WILDCARD", "HEX_WILDCARD", [](auto&& args) -> Value {
			std::vector<std::shared_ptr<HexStringUnit>> output;
			args[0].getTokenIt()->setType(TokenType::HEX_WILDCARD_LOW);
			auto first = std::make_shared<HexStringWildcard>(args[0].getTokenIt());
			args[1].getTokenIt()->setType(TokenType::HEX_WILDCARD_HIGH);
			auto second = std::make_shared<HexStringWildcard>(args[1].getTokenIt());
			output.reserve(2);
			output.push_back(std::move(first));
			output.push_back(std::move(second));
			return output;
		})
		;

	_parser.rule("hex_string_body") // vector<shared_ptr<HexStringUnit>>
		.production("hex_string_body", "hex_byte", [](auto&& args) -> Value {
			auto body = std::move(args[0].getMultipleHexUnits());
			auto byte = std::move(args[1].getMultipleHexUnits());
			std::move(byte.begin(), byte.end(), std::back_inserter(body));
			return body;
		})
		.production("hex_string_body", "hex_or", [](auto&& args) -> Value {
			auto body = std::move(args[0].getMultipleHexUnits());
			body.push_back(std::move(args[1].getHexUnit()));
			return body;
		})
		.production("hex_string_body", "hex_jump", [](auto&& args) -> Value {
			std::vector<std::shared_ptr<HexStringUnit>> body = std::move(args[0].getMultipleHexUnits());
			body.push_back(std::move(args[1].getHexUnit()));
			return body;
		})
		.production([](auto&&) -> Value { return std::vector<std::shared_ptr<HexStringUnit>>(); })
		;

	_parser.rule("hex_or") // shared_ptr<HexStringUnit>
		.production("LP", "hex_or_body", "RP", [](auto&& args) -> Value {
			args[0].getTokenIt()->setType(TokenType::HEX_ALT_LEFT_BRACKET);
			args[2].getTokenIt()->setType(TokenType::HEX_ALT_RIGHT_BRACKET);
			return std::make_shared<HexStringOr>(std::move(args[1].getMultipleHexStrings()));
		})
		;

	_parser.rule("hex_or_body") // vector<shared_ptr<yaramod::String>>
		.production("hex_string_body", [&](auto&& args) -> Value {
			std::vector<std::shared_ptr<HexString>> output;
			auto hexStr = std::make_shared<HexString>(currentFileContext()->getTokenStream(), std::move(args[0].getMultipleHexUnits()));
			output.push_back(std::move(hexStr));
			return output;
		})
		.production("hex_or_body", "HEX_OR", "hex_string_body", [&](auto&& args) -> Value {
			auto output = std::move(args[0].getMultipleHexStrings());
			auto hexStr = std::make_shared<HexString>(currentFileContext()->getTokenStream(), std::move(args[2].getMultipleHexUnits()));
			output.push_back(hexStr);
			return output;
		})
		;

	_parser.rule("hex_jump") // shared_ptr<HexStringUnit>
		.production("LSQB", "HEX_INTEGER", "RSQB", [](auto&& args) -> Value {
			args[0].getTokenIt()->setType(TokenType::HEX_JUMP_LEFT_BRACKET);
			args[2].getTokenIt()->setType(TokenType::HEX_JUMP_RIGHT_BRACKET);
			return std::make_shared<HexStringJump>(args[0].getTokenIt(), args[1].getTokenIt(), args[1].getTokenIt(), args[2].getTokenIt());
		})
		.production("LSQB", "HEX_INTEGER", "DASH", "HEX_INTEGER", "RSQB", [](auto&& args) -> Value {
			args[0].getTokenIt()->setType(TokenType::HEX_JUMP_LEFT_BRACKET);
			args[4].getTokenIt()->setType(TokenType::HEX_JUMP_RIGHT_BRACKET);
			return std::make_shared<HexStringJump>(args[0].getTokenIt(), args[1].getTokenIt(), args[3].getTokenIt(), args[4].getTokenIt());
		})
		.production("LSQB", "HEX_INTEGER", "DASH", "RSQB", [](auto&& args) -> Value {
			args[0].getTokenIt()->setType(TokenType::HEX_JUMP_LEFT_BRACKET);
			args[3].getTokenIt()->setType(TokenType::HEX_JUMP_RIGHT_BRACKET);
			return std::make_shared<HexStringJump>(args[0].getTokenIt(), args[1].getTokenIt(), args[3].getTokenIt());
		})
		.production("LSQB", "DASH", "RSQB", [](auto&& args) -> Value {
			args[0].getTokenIt()->setType(TokenType::HEX_JUMP_LEFT_BRACKET);
			args[2].getTokenIt()->setType(TokenType::HEX_JUMP_RIGHT_BRACKET);
			return std::make_shared<HexStringJump>(args[0].getTokenIt(), args[2].getTokenIt());
		})
		;

	_parser.rule("regexp") // shared_ptr<yaramod::String>
		.production("SLASH", "regexp_body", "SLASH", [](auto&& args) -> Value {
			auto regexp_string = std::move(args[1].getYaramodString());
			std::static_pointer_cast<Regexp>(regexp_string)->setSuffixModifiers(args[2].getString().substr(1));
			return regexp_string;
		})
		;

	_parser.rule("regexp_body") // shared_ptr<yaramod::String>
		.production("regexp_or", [&](auto&& args) -> Value { return Value(std::make_shared<Regexp>(currentFileContext()->getTokenStream(), std::move(args[0].getRegexpUnit()))); });

	_parser.rule("regexp_or") // shared_ptr<RegexpUnit>
		.production("regexp_concat", [](auto&& args) -> Value { return Value(std::make_shared<RegexpConcat>(std::move(args[0].getMultipleRegexpUnits()))); })
		.production("regexp_or", "REGEXP_OR", "regexp_concat", [](auto&& args) -> Value {
			std::shared_ptr<RegexpUnit> arg = std::move(args[0].getRegexpUnit());
			std::shared_ptr<RegexpUnit> concat = std::make_shared<RegexpConcat>(args[2].getMultipleRegexpUnits());
			return std::make_shared<RegexpOr>(std::move(arg), std::move(concat));
		})
		;

	_parser.rule("regexp_concat") // vector<shared_ptr<RegexpUnit>>
		.production("regexp_repeat", [](auto&& args) -> Value {
			std::vector<std::shared_ptr<yaramod::RegexpUnit>> output;
			output.push_back(std::move(args[0].getRegexpUnit()));
			return output;
		})
		.production("regexp_concat", "regexp_repeat", [](auto&& args) -> Value {
			auto output = std::move(args[0].getMultipleRegexpUnits());
			output.push_back(std::move(args[1].getRegexpUnit()));
			return output;
		})
		;

	_parser.rule("regexp_repeat") // shared_ptr<RegexpUnit>
		.production("regexp_single", "REGEXP_ITER", "regexp_greedy", [](auto&& args) -> Value {
			return std::make_shared<RegexpIteration>(std::move(args[0].getRegexpUnit()), args[2].getBool());
		})
		.production("regexp_single", "REGEXP_PITER", "regexp_greedy", [](auto&& args) -> Value {
			return std::make_shared<RegexpPositiveIteration>(std::move(args[0].getRegexpUnit()), args[2].getBool());
		})
		.production("regexp_single", "REGEXP_OPTIONAL", "regexp_greedy", [](auto&& args) -> Value {
			return std::make_shared<RegexpOptional>(std::move(args[0].getRegexpUnit()), args[2].getBool());
		})
		.production("regexp_single", "REGEXP_RANGE", "regexp_greedy", [&](auto&& args) -> Value {
			auto pair = std::move(args[1].getRegexpRangePair());
			if (!pair.first && !pair.second)
				error_handle(currentFileContext()->getLocation(), "Range in regular expression does not have defined lower bound nor higher bound");
			if (pair.first && pair.second && pair.first.value() > pair.second.value())
				error_handle(currentFileContext()->getLocation(), "Range in regular expression has greater lower bound than higher bound");
			return std::make_shared<RegexpRange>(std::move(args[0].getRegexpUnit()), std::move(pair), args[2].getBool());
		})
		.production("regexp_single", [](auto&& args) -> Value {
			return std::move(args[0]);
		})
		.production("REGEXP_WORD_BOUNDARY", [](auto&&) -> Value {
			return std::make_shared<RegexpWordBoundary>();
		})
		.production("REGEXP_NON_WORD_BOUNDARY", [](auto&&) -> Value {
			return std::make_shared<RegexpNonWordBoundary>();
		})
		.production("REGEXP_START_OF_LINE", [](auto&&) -> Value {
			return std::make_shared<RegexpStartOfLine>();
		})
		.production("REGEXP_END_OF_LINE", [](auto&&) -> Value {
			return std::make_shared<RegexpEndOfLine>();
		})
		;

	_parser.rule("regexp_greedy") // bool
		.production([](auto&&) -> Value { return true; })
		.production("REGEXP_OPTIONAL", [](auto&&) -> Value { return false; })
		;

	_parser.rule("regexp_single") // shared_ptr<yaramod::RegexpUnit>
		.production("LP", "regexp_or", "RP", [](auto&& args) -> Value { return Value(std::make_shared<RegexpGroup>(std::move(args[1].getRegexpUnit()))); })
		.production("REGEXP_ANY_CHAR", [](auto&&) -> Value { return Value(std::make_shared<RegexpAnyChar>()); })
		.production("REGEXP_ESCAPE", [](auto&& args) -> Value { return Value(std::make_shared<RegexpText>(std::move(args[0].getString()))); })
		.production("REGEXP_CHAR", [](auto&& args) -> Value { return Value(std::make_shared<RegexpText>(std::move(args[0].getString()))); })
		.production("REGEXP_WORD_CHAR", [](auto&&) -> Value { return Value(std::make_shared<RegexpWordChar>()); })
		.production("REGEXP_NON_WORD_CHAR", [](auto&&) -> Value { return Value(std::make_shared<RegexpNonWordChar>()); })
		.production("REGEXP_SPACE", [](auto&&) -> Value { return Value(std::make_shared<RegexpSpace>()); })
		.production("REGEXP_NON_SPACE", [](auto&&) -> Value { return Value(std::make_shared<RegexpNonSpace>()); })
		.production("REGEXP_DIGIT", [](auto&&) -> Value { return Value(std::make_shared<RegexpDigit>()); })
		.production("REGEXP_NON_DIGIT", [](auto&&) -> Value { return Value(std::make_shared<RegexpNonDigit>()); })
		.production("REGEXP_CLASS", [&](auto&& args) -> Value {
			auto record = std::move(args[0].getRegexpClassRecord());
			if (!record.first)
				return Value(std::make_shared<RegexpText>(std::string{}));
			auto c = record.second;
			if (!c.empty() && c[0] == '^')
				return std::make_shared<RegexpClass>(c.substr(1, c.length() - 1), true);
			else
				return std::make_shared<RegexpClass>(std::move(c), false);
		})
		;

	_parser.rule("condition") // Expression::Ptr
		.production("CONDITION", "COLON", "expression", [](auto&& args) -> Value {
			args[1].getTokenIt()->setType(TokenType::COLON_BEFORE_NEWLINE);
			return std::move(args[2]);
		})
		;

	auto& expr = _parser.rule("expression") // Expression::Ptr
		.production("boolean", [&](auto&& args) -> Value {
			auto output = std::make_shared<BoolLiteralExpression>(currentTokenStream(), args[0].getTokenIt());
			output->setType(Expression::Type::Bool);
			return output;
		})
		.production("STRING_ID", [&](auto&& args) -> Value {
			TokenIt id = args[0].getTokenIt();
			assert(id->isString());
			if (!stringExists(id->getString()))
				error_handle(id->getLocation(), "Reference to undefined string '" + id->getString() + "'");
			if (id->getString().size() > 1)
				id->setValue(findStringDefinition(id->getString()));
			auto output = std::make_shared<StringExpression>(std::move(id));
			output->setType(Expression::Type::Bool);
			output->setTokenStream(currentTokenStream());
			return output;
		})
		.production("STRING_ID", "AT", "primary_expression", [&](auto&& args) -> Value {
			TokenIt id = args[0].getTokenIt();
			assert(id->isString());
			if (!stringExists(id->getString()))
				error_handle(id->getLocation(), "Reference to undefined string '" + id->getString() + "'");
			if (id->getString().size() > 1)
				id->setValue(findStringDefinition(id->getString()));
			TokenIt op = args[1].getTokenIt();
			Expression::Ptr expr = args[2].getExpression();
			if (!expr->isInt())
				error_handle(args[1].getTokenIt()->getLocation(), "Operator 'at' expects integer on the right-hand side of the expression");
			auto output = std::make_shared<StringAtExpression>(id, op, std::move(expr));
			output->setType(Expression::Type::Bool);
			output->setTokenStream(currentTokenStream());
			return output;
		})
		.production("STRING_ID", "IN", "range", [&](auto&& args) -> Value {
			TokenIt id = args[0].getTokenIt();
			assert(id->isString());
			if (!stringExists(id->getString()))
				error_handle(id->getLocation(), "Reference to undefined string '" + id->getString() + "'");
			if (id->getString().size() > 1)
				id->setValue(findStringDefinition(id->getString()));
			TokenIt op = args[1].getTokenIt();
			Expression::Ptr range = args[2].getExpression();

			auto output = std::make_shared<StringInRangeExpression>(id, op, std::move(range));
			output->setType(Expression::Type::Bool);
			output->setTokenStream(currentTokenStream());
			return output;
		})
		.production(
			"FOR", "for_expression", "ID", "IN", "integer_set", [&](auto&& args) -> Value {
				auto symbol = std::make_shared<ValueSymbol>(args[2].getTokenIt()->getString(), Expression::Type::Int);
				if (!addLocalSymbol(symbol))
					error_handle(args[2].getTokenIt()->getLocation(), "Redefinition of identifier '" + args[2].getTokenIt()->getString() + "'");
				return {};
			},
			"COLON", "LP", "expression", "RP", [&](auto&& args) -> Value {
				TokenIt for_token = args[0].getTokenIt();
				auto for_expr = std::move(args[1].getExpression());
				TokenIt id = args[2].getTokenIt();

				TokenIt op_in = args[3].getTokenIt();
				auto set = std::move(args[4].getExpression());
				TokenIt lp = args[7].getTokenIt();
				auto expr = args[8].getExpression();
				TokenIt rp = args[9].getTokenIt();

				removeLocalSymbol(id->getString());
				lp->setType(TokenType::LP_WITH_SPACE_AFTER);
				rp->setType(TokenType::RP_WITH_SPACE_BEFORE);
				auto output = std::make_shared<ForArrayExpression>(for_token, std::move(for_expr), id, op_in, std::move(set), lp, std::move(expr), rp);
				output->setType(Expression::Type::Bool);
				output->setTokenStream(currentTokenStream());
				return output;
			}
		)
		.production(
			"FOR", "for_expression", "ID", "IN", "identifier", [&](auto&& args) -> Value {
				const auto& iterable = args[4].getExpression();
				std::shared_ptr<Symbol> parentSymbol = std::static_pointer_cast<const IdExpression>(iterable)->getSymbol();
				assert(parentSymbol);
				if (!parentSymbol->isArray())
				{
					if (!incompleteMode() || !parentSymbol->isUndefined())
						error_handle((++args[3].getTokenIt())->getLocation(), "Identifier '" + parentSymbol->getName() + "' is not an array");
					else
					{
						auto parentExpr = std::static_pointer_cast<IdExpression>(iterable);
						const auto& parentTokenText = parentExpr->getSymbolToken()->getText();
						parentExpr->setSymbol(std::make_shared<ArraySymbol>(parentTokenText, ExpressionType::Undefined));
					}
				}

				std::shared_ptr<const ArraySymbol> iterParentSymbol = std::static_pointer_cast<const ArraySymbol>(parentSymbol);

				std::shared_ptr<Symbol> symbol;
				if (iterParentSymbol->isStructured())
				{
					auto s = std::static_pointer_cast<const StructureSymbol>(iterParentSymbol->getStructuredElementType());
					symbol = std::make_shared<StructureSymbol>(*s);
					symbol->setName(args[2].getTokenIt()->getString());
				}
				else
				{
					symbol = std::make_shared<ValueSymbol>(args[2].getTokenIt()->getString(), iterParentSymbol->getElementType());
				}

				if (!addLocalSymbol(symbol))
					error_handle(args[2].getTokenIt()->getLocation(), "Redefinition of identifier '" + args[2].getTokenIt()->getString() + "'");
				return {};
			},
			"COLON", "LP", "expression", "RP", [&](auto&& args) -> Value {
				TokenIt for_token = args[0].getTokenIt();
				auto for_expr = std::move(args[1].getExpression());
				TokenIt id = args[2].getTokenIt();
				TokenIt op_in = args[3].getTokenIt();
				auto array = std::move(args[4].getExpression());

				TokenIt lp = args[7].getTokenIt();
				auto expr = args[8].getExpression();
				TokenIt rp = args[9].getTokenIt();

				removeLocalSymbol(id->getString());
				lp->setType(TokenType::LP_WITH_SPACE_AFTER);
				rp->setType(TokenType::RP_WITH_SPACE_BEFORE);
				auto output = std::make_shared<ForArrayExpression>(for_token, std::move(for_expr), id, op_in, std::move(array), lp, std::move(expr), rp);
				output->setType(Expression::Type::Bool);
				output->setTokenStream(currentTokenStream());
				return output;
			}
		)
		.production(
			"FOR", "for_expression", "ID", "COMMA", "ID", "IN", "identifier", [&](auto&& args) -> Value {
				const auto& iterable = args[6].getExpression();
				std::shared_ptr<Symbol> parentSymbol = std::static_pointer_cast<const IdExpression>(iterable)->getSymbol();
				assert(parentSymbol);
				if (!parentSymbol->isDictionary())
				{
					if (!incompleteMode() || !parentSymbol->isUndefined())
						error_handle((++args[5].getTokenIt())->getLocation(), "Identifier '" + parentSymbol->getName() + "' is not an dictionary");
					else
					{
						auto parentExpr = std::static_pointer_cast<IdExpression>(iterable);
						const auto& parentTokenText = parentExpr->getSymbolToken()->getText();
						parentExpr->setSymbol(std::make_shared<DictionarySymbol>(parentTokenText, ExpressionType::Undefined));
					}
				}

				std::shared_ptr<Symbol> symbol1 = std::make_shared<ValueSymbol>(args[2].getTokenIt()->getString(), ExpressionType::String);
				if (!addLocalSymbol(symbol1))
					error_handle(args[2].getTokenIt()->getLocation(), "Redefinition of identifier '" + args[2].getTokenIt()->getString() + "'");

				std::shared_ptr<const DictionarySymbol> iterParentSymbol = std::static_pointer_cast<const DictionarySymbol>(parentSymbol);

				std::shared_ptr<Symbol> symbol2;
				if (iterParentSymbol->isStructured())
				{
					auto s = std::static_pointer_cast<const StructureSymbol>(iterParentSymbol->getStructuredElementType());
					symbol2 = std::make_shared<StructureSymbol>(*s);
					symbol2->setName(args[4].getTokenIt()->getString());
				}
				else
				{
					symbol2 = std::make_shared<ValueSymbol>(args[4].getTokenIt()->getString(), iterParentSymbol->getElementType());
				}

				if (!addLocalSymbol(symbol2))
					error_handle(args[4].getTokenIt()->getLocation(), "Redefinition of identifier '" + args[4].getTokenIt()->getString() + "'");
				return {};
			},
			"COLON", "LP", "expression", "RP", [&](auto&& args) -> Value {
				TokenIt for_token = args[0].getTokenIt();
				auto for_expr = std::move(args[1].getExpression());
				TokenIt id1 = args[2].getTokenIt();
				TokenIt comma = args[3].getTokenIt();
				TokenIt id2 = args[4].getTokenIt();
				TokenIt op_in = args[5].getTokenIt();
				auto dict = std::move(args[6].getExpression());

				TokenIt lp = args[9].getTokenIt();
				auto expr = args[10].getExpression();
				TokenIt rp = args[11].getTokenIt();

				removeLocalSymbol(id1->getString());
				removeLocalSymbol(id2->getString());
				lp->setType(TokenType::LP_WITH_SPACE_AFTER);
				rp->setType(TokenType::RP_WITH_SPACE_BEFORE);
				auto output = std::make_shared<ForDictExpression>(for_token, std::move(for_expr), id1, comma, id2, op_in, std::move(dict), lp, std::move(expr), rp);
				output->setType(Expression::Type::Bool);
				output->setTokenStream(currentTokenStream());
				return output;
			}
		)
		.production(
			"FOR", "for_expression", "OF", "string_set", [&](auto&& args) -> Value {
				if (isInStringLoop())
					error_handle(args[0].getTokenIt()->getLocation(), "Nesting of for-loop over strings is not allowed");
				stringLoopEnter();
				return {};
			},
			"COLON", "LP", "expression", "RP", [&](auto&& args) -> Value {
				TokenIt for_token = args[0].getTokenIt();
				auto for_expr = std::move(args[1].getExpression());
				TokenIt of = args[2].getTokenIt();
				auto set = std::move(args[3].getExpression());

				TokenIt lp = args[6].getTokenIt();
				auto expr = args[7].getExpression();
				TokenIt rp = args[8].getTokenIt();

				lp->setType(TokenType::LP_WITH_SPACE_AFTER);
				rp->setType(TokenType::RP_WITH_SPACE_BEFORE);
				auto output = std::make_shared<ForStringExpression>(for_token, std::move(for_expr), of, std::move(set), lp, std::move(expr), rp);
				output->setType(Expression::Type::Bool);
				output->setTokenStream(currentTokenStream());
				stringLoopLeave();
				return output;
			}
		)
		.production("for_expression", "OF", "string_set", [&](auto&& args) -> Value {
			auto for_expr = std::move(args[0].getExpression());
			TokenIt of = args[1].getTokenIt();
			auto set = std::move(args[2].getExpression());
			auto output = std::make_shared<OfExpression>(std::move(for_expr), of, std::move(set));
			output->setType(Expression::Type::Bool);
			output->setTokenStream(currentTokenStream());
			return output;
		})
		.production("for_expression", "OF", "rule_set", [&](auto&& args) -> Value {
			auto for_expr = std::move(args[0].getExpression());
			TokenIt of = args[1].getTokenIt();
			auto set = std::move(args[2].getExpression());
			auto output = std::make_shared<OfExpression>(std::move(for_expr), of, std::move(set));
			output->setType(Expression::Type::Bool);
			output->setTokenStream(currentTokenStream());
			return output;
		})
		.production("for_expression", "OF", "string_set", "IN", "range", [&](auto&& args) -> Value {
			auto for_expr = std::move(args[0].getExpression());
			TokenIt of = args[1].getTokenIt();
			auto set = std::move(args[2].getExpression());
			TokenIt in = args[3].getTokenIt();
			auto range = args[4].getExpression();
			auto output = std::make_shared<OfExpression>(std::move(for_expr), of, std::move(set), in, std::move(range));
			output->setType(Expression::Type::Bool);
			output->setTokenStream(currentTokenStream());
			return output;
		})
		.production("primary_expression", "PERCENT", "OF", "string_set", [&](auto&& args) -> Value {
			auto for_expr = std::move(args[0].getExpression());
			TokenIt percent = args[1].getTokenIt();
			std::uint64_t value = 0;
			if (strToNum(for_expr->getText(), value))
			{
				if (value == 0 || value > 100)
				{
					std::stringstream ss;
					ss << "Percentage must be between 1 and 100 (inclusive). Got " << value << ".";
					error_handle(percent->getLocation(), ss.str());
				}
			}
			auto percentual_expr = std::make_shared<PercentualExpression>(std::move(for_expr), percent);
			TokenIt of = args[2].getTokenIt();
			auto set = std::move(args[3].getExpression());
			auto output = std::make_shared<OfExpression>(std::move(percentual_expr), of, std::move(set));
			output->setType(Expression::Type::Bool);
			output->setTokenStream(currentTokenStream());
			return output;
		})
		.production("NOT", "expression", [&](auto&& args) -> Value {
			TokenIt not_token = args[0].getTokenIt();
			auto expr = std::move(args[1].getExpression());
			auto output = std::make_shared<NotExpression>(not_token, std::move(expr));
			output->setType(Expression::Type::Bool);
			output->setTokenStream(currentTokenStream());
			return output;
		})
		.production("DEFINED", "expression", [&](auto&& args) -> Value {
			TokenIt not_token = args[0].getTokenIt();
			auto expr = std::move(args[1].getExpression());
			auto output = std::make_shared<DefinedExpression>(not_token, std::move(expr));
			output->setType(Expression::Type::Bool);
			output->setTokenStream(currentTokenStream());
			return output;
		})
		.production("expression", "AND", "expression", [&](auto&& args) -> Value {
			auto left = std::move(args[0].getExpression());
			TokenIt and_token = args[1].getTokenIt();
			auto right = std::move(args[2].getExpression());
			auto output = std::make_shared<AndExpression>(std::move(left), and_token, std::move(right));
			output->setType(Expression::Type::Bool);
			output->setTokenStream(currentTokenStream());
			return output;
		})
		.production("expression", "OR", "expression", [&](auto&& args) -> Value {
			auto left = std::move(args[0].getExpression());
			TokenIt or_token = args[1].getTokenIt();
			auto right = std::move(args[2].getExpression());
			auto output = std::make_shared<OrExpression>(std::move(left), or_token, std::move(right));
			output->setType(Expression::Type::Bool);
			output->setTokenStream(currentTokenStream());
			return output;
		})
		.production("primary_expression", "LT", "primary_expression", [&](auto&& args) -> Value {
			auto left = std::move(args[0].getExpression());
			TokenIt op_token = args[1].getTokenIt();
			auto right = std::move(args[2].getExpression());
			auto output = std::make_shared<LtExpression>(std::move(left), op_token, std::move(right));
			output->setType(Expression::Type::Bool);
			output->setTokenStream(currentTokenStream());
			return output;
		})
		.production("primary_expression", "GT", "primary_expression", [&](auto&& args) -> Value {
			auto left = std::move(args[0].getExpression());
			TokenIt op_token = args[1].getTokenIt();
			auto right = std::move(args[2].getExpression());
			auto output = std::make_shared<GtExpression>(std::move(left), op_token, std::move(right));
			output->setType(Expression::Type::Bool);
			output->setTokenStream(currentTokenStream());
			return output;
		})
		.production("primary_expression", "LE", "primary_expression", [&](auto&& args) -> Value {
			auto left = std::move(args[0].getExpression());
			TokenIt op_token = args[1].getTokenIt();
			auto right = std::move(args[2].getExpression());
			auto output = std::make_shared<LeExpression>(std::move(left), op_token, std::move(right));
			output->setType(Expression::Type::Bool);
			output->setTokenStream(currentTokenStream());
			return output;
		})
		.production("primary_expression", "GE", "primary_expression", [&](auto&& args) -> Value {
			auto left = std::move(args[0].getExpression());
			TokenIt op_token = args[1].getTokenIt();
			auto right = std::move(args[2].getExpression());
			auto output = std::make_shared<GeExpression>(std::move(left), op_token, std::move(right));
			output->setType(Expression::Type::Bool);
			output->setTokenStream(currentTokenStream());
			return output;
		})
		.production("primary_expression", "EQ", "primary_expression", [&](auto&& args) -> Value {
			auto left = std::move(args[0].getExpression());
			TokenIt op_token = args[1].getTokenIt();
			auto right = std::move(args[2].getExpression());
			auto output = std::make_shared<EqExpression>(std::move(left), op_token, std::move(right));
			output->setType(Expression::Type::Bool);
			output->setTokenStream(currentTokenStream());
			return output;
		})
		.production("primary_expression", "NEQ", "primary_expression", [&](auto&& args) -> Value {
			auto left = std::move(args[0].getExpression());
			TokenIt op_token = args[1].getTokenIt();
			auto right = std::move(args[2].getExpression());
			auto output = std::make_shared<NeqExpression>(std::move(left), op_token, std::move(right));
			output->setType(Expression::Type::Bool);
			output->setTokenStream(currentTokenStream());
			return output;
		})
		.production("primary_expression", "CONTAINS", "primary_expression", [&](auto&& args) -> Value {
			auto left = std::move(args[0].getExpression());
			TokenIt op_token = args[1].getTokenIt();
			auto right = std::move(args[2].getExpression());
			if (!left->isString())
				error_handle(op_token->getLocation(), "operator 'contains' expects string on the left-hand side of the expression");
			if (!right->isString())
				error_handle(op_token->getLocation(), "operator 'contains' expects string on the right-hand side of the expression");
			auto output = std::make_shared<ContainsExpression>(std::move(left), op_token, std::move(right));
			output->setType(Expression::Type::Bool);
			output->setTokenStream(currentTokenStream());
			return output;
		})
		.production("primary_expression", "MATCHES", "regexp", [&](auto&& args) -> Value {
			auto left = std::move(args[0].getExpression());
			TokenIt op_token = args[1].getTokenIt();
			auto right = std::move(args[2].getYaramodString());
			if (!left->isString())
				error_handle(op_token->getLocation(), "operator 'matches' expects string on the left-hand side of the expression");
			auto regexp_expression = std::make_shared<RegexpExpression>(std::move(right));
			auto output = std::make_shared<MatchesExpression>(std::move(left), op_token, std::move(regexp_expression));
			output->setType(Expression::Type::Bool);
			output->setTokenStream(currentTokenStream());
			return output;
		})
		.production("primary_expression", "IEQUALS", "primary_expression", [&](auto&& args) -> Value {
			auto left = std::move(args[0].getExpression());
			TokenIt op_token = args[1].getTokenIt();
			auto right = std::move(args[2].getExpression());
			if (!left->isString())
				error_handle(op_token->getLocation(), "operator 'iequals' expects string on the left-hand side of the expression");
			if (!right->isString())
				error_handle(op_token->getLocation(), "operator 'iequals' expects string on the right-hand side of the expression");
			auto output = std::make_shared<IequalsExpression>(std::move(left), op_token, std::move(right));
			output->setType(Expression::Type::Bool);
			output->setTokenStream(currentTokenStream());
			return output;
		})
		.production("primary_expression", [](auto&& args) -> Value {
			return std::move(args[0]);
		}).precedence(0, pog::Associativity::Left)
		.production("LP", "expression", "RP", [&](auto&& args) -> Value {
			auto expr = std::move(args[1].getExpression());
			auto type = expr->getType();
			auto output = std::make_shared<ParenthesesExpression>(args[0].getTokenIt(), std::move(expr), args[2].getTokenIt());
			output->setType(type);
			output->setTokenStream(currentTokenStream());
			return output;
		})
		;

	if (_features & Features::AvastOnly)
		expr.production("for_expression", "OF", "expression_iterable", [this](auto&& args) -> Value {
			auto for_expr = std::move(args[0].getExpression());
			TokenIt of = args[1].getTokenIt();
			auto array = std::move(args[2].getExpression());
			auto output = std::make_shared<OfExpression>(std::move(for_expr), of, std::move(array));
			output->setType(Expression::Type::Bool);
			output->setTokenStream(currentTokenStream());
			return output;
		})
		;

	_parser.rule("primary_expression") // Expression::Ptr
		.production("LP", "primary_expression", "RP", [&](auto&& args) -> Value {
			auto type = args[1].getExpression()->getType();
			auto output = std::make_shared<ParenthesesExpression>(args[0].getTokenIt(), std::move(args[1].getExpression()), args[2].getTokenIt());
			output->setType(type);
			output->setTokenStream(currentTokenStream());
			return output;
		})
		.production("FILESIZE", [&](auto&& args) -> Value {
			auto output = std::make_shared<FilesizeExpression>(args[0].getTokenIt());
			output->setType(Expression::Type::Int);
			output->setTokenStream(currentTokenStream());
			return output;
		})
		.production("ENTRYPOINT", [&](auto&& args) -> Value {
			auto output = std::make_shared<EntrypointExpression>(args[0].getTokenIt());
			output->setType(Expression::Type::Int);
			return output;
		})
		.production("INTEGER", [&](auto&& args) -> Value {
			auto output = std::make_shared<IntLiteralExpression>(currentTokenStream(), args[0].getTokenIt());
			output->setType(Expression::Type::Int);
			return output;
		})
		.production("DOUBLE", [&](auto&& args) -> Value {
			auto output = std::make_shared<DoubleLiteralExpression>(currentTokenStream(), args[0].getTokenIt());
			output->setType(Expression::Type::Float);
			return output;
		})
		.production("STRING_LITERAL", [&](auto&& args) -> Value {
			auto output = std::make_shared<StringLiteralExpression>(currentTokenStream(), args[0].getTokenIt());
			output->setType(Expression::Type::String);
			return output;
		})
		.production("STRING_COUNT", [&](auto&& args) -> Value {
			// Replace '#' for '$' to get string id
			TokenIt id = args[0].getTokenIt();
			auto stringId = id->getString();
			stringId[0] = '$';

			if (!stringExists(stringId))
				error_handle(args[0].getTokenIt()->getLocation(), "Reference to undefined string '" + args[0].getTokenIt()->getString() + "'");
			if (stringId.size() > 1)
				id->setValue(findStringDefinition(stringId));
			auto output = std::make_shared<StringCountExpression>(args[0].getTokenIt());
			output->setType(Expression::Type::Int);
			output->setTokenStream(currentTokenStream());
			return output;
		})
		.production("STRING_COUNT", "IN", "range", [&](auto&& args) -> Value {
			TokenIt id = args[0].getTokenIt();
			auto stringId = id->getString();
			stringId[0] = '$';

			if (!stringExists(stringId))
				error_handle(id->getLocation(), "Reference to undefined string '" + stringId + "'");
			if (id->getString().size() > 1)
				id->setValue(findStringDefinition(stringId));
			Expression::Ptr range = args[2].getExpression();

			auto output = std::make_shared<StringInRangeExpression>(args[0].getTokenIt(), args[1].getTokenIt(), std::move(range));
			output->setType(Expression::Type::Int);
			output->setTokenStream(currentTokenStream());
			return output;
		})
		.production("STRING_OFFSET", [&](auto&& args) -> Value {
			// Replace '@' for '$' to get string id
			TokenIt id = args[0].getTokenIt();
			auto stringId = id->getString();
			stringId[0] = '$';

			if (!stringExists(stringId))
				error_handle(args[0].getTokenIt()->getLocation(), "Reference to undefined string '" + args[0].getTokenIt()->getString() + "'");
			if (stringId.size() > 1)
				id->setValue(findStringDefinition(stringId));
			auto output = std::make_shared<StringOffsetExpression>(args[0].getTokenIt());
			output->setType(Expression::Type::Int);
			output->setTokenStream(currentTokenStream());
			return output;
		})
		.production("STRING_OFFSET", "LSQB", "primary_expression", "RSQB", [&](auto&& args) -> Value {
			// Replace '@' for '$' to get string id
			TokenIt id = args[0].getTokenIt();
			auto stringId = id->getString();
			stringId[0] = '$';

			if (!stringExists(stringId))
				error_handle(args[0].getTokenIt()->getLocation(), "Reference to undefined string '" + args[0].getTokenIt()->getString() + "'");
			if (stringId.size() > 1)
				id->setValue(findStringDefinition(stringId));
			auto output = std::make_shared<StringOffsetExpression>(args[0].getTokenIt(), std::move(args[2].getExpression()));
			output->setType(Expression::Type::Int);
			output->setTokenStream(currentTokenStream());
			return output;
		})
		.production("STRING_LENGTH", [&](auto&& args) -> Value {
			// Replace '!' for '$' to get string id
			TokenIt id = args[0].getTokenIt();
			auto stringId = id->getString();
			stringId[0] = '$';

			if (!stringExists(stringId))
				error_handle(args[0].getTokenIt()->getLocation(), "Reference to undefined string '" + args[0].getTokenIt()->getString() + "'");
			if (stringId.size() > 1)
				id->setValue(findStringDefinition(stringId));
			auto output = std::make_shared<StringLengthExpression>(args[0].getTokenIt());
			output->setType(Expression::Type::Int);
			output->setTokenStream(currentTokenStream());
			return output;
		})
		.production("STRING_LENGTH", "LSQB", "primary_expression", "RSQB", [&](auto&& args) -> Value {
			// Replace '!' for '$' to get string id
			TokenIt id = args[0].getTokenIt();
			auto stringId = id->getString();
			stringId[0] = '$';

			if (!stringExists(stringId))
				error_handle(args[0].getTokenIt()->getLocation(), "Reference to undefined string '" + args[0].getTokenIt()->getString() + "'");
			if (stringId.size() > 1)
				id->setValue(findStringDefinition(stringId));
			auto output = std::make_shared<StringLengthExpression>(args[0].getTokenIt(), std::move(args[2].getExpression()));
			output->setType(Expression::Type::Int);
			output->setTokenStream(currentTokenStream());
			return output;
		})
		.production("MINUS", "primary_expression", [&](auto&& args) -> Value {
			auto right = args[1].getExpression();
			if (!right->isInt() && !right->isFloat())
			{
				error_handle(args[0].getTokenIt()->getLocation(), "unary minus expects integer or float type");
			}
			auto type = right->getType();
			args[0].getTokenIt()->setType(TokenType::UNARY_MINUS);
			auto output = std::make_shared<UnaryMinusExpression>(args[0].getTokenIt(), std::move(right));
			output->setType(type);
			output->setTokenStream(currentTokenStream());
			return output;
		}).precedence(3, pog::Associativity::Right)
		.production("primary_expression", "PLUS", "primary_expression", [&](auto&& args) -> Value {
			auto left = args[0].getExpression();
			auto right = args[2].getExpression();
			if (!left->isInt() && !left->isFloat())
				error_handle(args[1].getTokenIt()->getLocation(), "operator '+' expects integer or float on the left-hand side");
			if (!right->isInt() && !right->isFloat())
				error_handle(args[1].getTokenIt()->getLocation(), "operator '+' expects integer or float on the right-hand side");
			auto type = (left->isInt() && right->isInt()) ? Expression::Type::Int : Expression::Type::Float;
			auto output = std::make_shared<PlusExpression>(std::move(left), args[1].getTokenIt(), std::move(right));
			output->setType(type);
			output->setTokenStream(currentTokenStream());
			return output;
		})
		.production("primary_expression", "MINUS", "primary_expression", [&](auto&& args) -> Value {
			auto left = args[0].getExpression();
			auto right = args[2].getExpression();
			if (!left->isInt() && !left->isFloat())
				error_handle(args[1].getTokenIt()->getLocation(), "operator '-' expects integer or float on the left-hand side");
			if (!right->isInt() && !right->isFloat())
				error_handle(args[1].getTokenIt()->getLocation(), "operator '-' expects integer or float on the right-hand side");
			auto type = (left->isInt() && right->isInt()) ? Expression::Type::Int : Expression::Type::Float;
			auto output = std::make_shared<MinusExpression>(std::move(left), args[1].getTokenIt(), std::move(right));
			output->setType(type);
			output->setTokenStream(currentTokenStream());
			return output;
		})
		.production("primary_expression", "MULTIPLY", "primary_expression", [&](auto&& args) -> Value {
			auto left = args[0].getExpression();
			auto right = args[2].getExpression();
			if (!left->isInt() && !left->isFloat())
				error_handle(args[1].getTokenIt()->getLocation(), "operator '*' expects integer or float on the left-hand side");
			if (!right->isInt() && !right->isFloat())
				error_handle(args[1].getTokenIt()->getLocation(), "operator '*' expects integer or float on the right-hand side");
			auto type = (left->isInt() && right->isInt()) ? Expression::Type::Int : Expression::Type::Float;
			auto output = std::make_shared<MultiplyExpression>(std::move(left), args[1].getTokenIt(), std::move(right));
			output->setType(type);
			output->setTokenStream(currentTokenStream());
			return output;
		})
		.production("primary_expression", "DIVIDE", "primary_expression", [&](auto&& args) -> Value {
			auto left = args[0].getExpression();
			auto right = args[2].getExpression();
			if (!left->isInt() && !left->isFloat())
				error_handle(args[1].getTokenIt()->getLocation(), "operator '\\' expects integer or float on the left-hand side");
			if (!right->isInt() && !right->isFloat())
				error_handle(args[1].getTokenIt()->getLocation(), "operator '\\' expects integer or float on the right-hand side");
			auto type = (left->isInt() && right->isInt()) ? Expression::Type::Int : Expression::Type::Float;
			auto output = std::make_shared<DivideExpression>(std::move(left), args[1].getTokenIt(), std::move(right));
			output->setType(type);
			output->setTokenStream(currentTokenStream());
			return output;
		})
		.production("primary_expression", "PERCENT", "primary_expression", [&](auto&& args) -> Value {
			auto left = args[0].getExpression();
			auto right = args[2].getExpression();
			if (!left->isInt() && !left->isFloat())
				error_handle(args[1].getTokenIt()->getLocation(), "operator '%' expects integer or float on the left-hand side");
			if (!right->isInt() && !right->isFloat())
				error_handle(args[1].getTokenIt()->getLocation(), "operator '%' expects integer or float on the right-hand side");
			auto output = std::make_shared<ModuloExpression>(std::move(left), args[1].getTokenIt(), std::move(right));
			output->setType(Expression::Type::Int);
			output->setTokenStream(currentTokenStream());
			return output;
		})
		.production("primary_expression", "BITWISE_XOR", "primary_expression", [&](auto&& args) -> Value {
			auto left = args[0].getExpression();
			auto right = args[2].getExpression();
			if (!left->isInt() && !left->isFloat())
				error_handle(args[1].getTokenIt()->getLocation(), "operator '^' expects integer or float on the left-hand side");
			if (!right->isInt() && !right->isFloat())
				error_handle(args[1].getTokenIt()->getLocation(), "operator '^' expects integer or float on the right-hand side");
			auto output = std::make_shared<BitwiseXorExpression>(std::move(left), args[1].getTokenIt(), std::move(right));
			output->setType(Expression::Type::Int);
			output->setTokenStream(currentTokenStream());
			return output;
		})
		.production("primary_expression", "BITWISE_AND", "primary_expression", [&](auto&& args) -> Value {
			auto left = args[0].getExpression();
			auto right = args[2].getExpression();
			if (!left->isInt() && !left->isFloat())
				error_handle(args[1].getTokenIt()->getLocation(), "operator '&' expects integer or float on the left-hand side");
			if (!right->isInt() && !right->isFloat())
				error_handle(args[1].getTokenIt()->getLocation(), "operator '&' expects integer or float on the right-hand side");
			auto output = std::make_shared<BitwiseAndExpression>(std::move(left), args[1].getTokenIt(), std::move(right));
			output->setType(Expression::Type::Int);
			output->setTokenStream(currentTokenStream());
			return output;
		})
		.production("primary_expression", "BITWISE_OR", "primary_expression", [&](auto&& args) -> Value {
			auto left = args[0].getExpression();
			auto right = args[2].getExpression();
			if (!left->isInt() && !left->isFloat())
				error_handle(args[1].getTokenIt()->getLocation(), "operator '|' expects integer or float on the left-hand side");
			if (!right->isInt() && !right->isFloat())
				error_handle(args[1].getTokenIt()->getLocation(), "operator '|' expects integer or float on the right-hand side");
			auto output = std::make_shared<BitwiseOrExpression>(std::move(left), args[1].getTokenIt(), std::move(right));
			output->setType(Expression::Type::Int);
			output->setTokenStream(currentTokenStream());
			return output;
		})
		.production("BITWISE_NOT", "primary_expression", [&](auto&& args) -> Value {
			auto right = args[1].getExpression();
			if (!right->isInt())
				error_handle(args[0].getTokenIt()->getLocation(), "bitwise not expects integer");
			auto output = std::make_shared<BitwiseNotExpression>(args[0].getTokenIt(), std::move(right));
			output->setType(Expression::Type::Int);
			output->setTokenStream(currentTokenStream());
			return output;
		})
		.production("primary_expression", "SHIFT_LEFT", "primary_expression", [&](auto&& args) -> Value {
			auto left = args[0].getExpression();
			auto right = args[2].getExpression();
			if (!left->isInt() && !left->isFloat())
				error_handle(args[1].getTokenIt()->getLocation(), "operator '<<' expects integer on the left-hand side");
			if (!right->isInt() && !right->isFloat())
				error_handle(args[1].getTokenIt()->getLocation(), "operator '<<' expects integer on the right-hand side");
			auto output = std::make_shared<ShiftLeftExpression>(std::move(left), args[1].getTokenIt(), std::move(right));
			output->setType(Expression::Type::Int);
			output->setTokenStream(currentTokenStream());
			return output;
		})
		.production("primary_expression", "SHIFT_RIGHT", "primary_expression", [&](auto&& args) -> Value {
			auto left = args[0].getExpression();
			auto right = args[2].getExpression();
			if (!left->isInt() && !left->isFloat())
				error_handle(args[1].getTokenIt()->getLocation(), "operator '>>' expects integer on the left-hand side");
			if (!right->isInt() && !right->isFloat())
				error_handle(args[1].getTokenIt()->getLocation(), "operator '>>' expects integer on the right-hand side");
			auto output = std::make_shared<ShiftRightExpression>(std::move(left), args[1].getTokenIt(), std::move(right));
			output->setType(Expression::Type::Int);
			output->setTokenStream(currentTokenStream());
			return output;
		})
		.production("INTEGER_FUNCTION", "LP", "primary_expression", "RP", [&](auto&& args) -> Value {
			if (!args[2].getExpression()->isInt())
				error_handle(args[0].getTokenIt()->getLocation(), "operator '" + args[0].getTokenIt()->getString() + "' expects integer");
			auto output = std::make_shared<IntFunctionExpression>(std::move(args[0].getTokenIt()), std::move(args[1].getTokenIt()), std::move(args[2].getExpression()), std::move(args[3].getTokenIt()));
			output->setType(Expression::Type::Int);
			output->setTokenStream(currentTokenStream());
			return output;
		})
		.production("identifier", [](auto&& args) -> Value {
			return std::move(args[0]);
		})
		.production("regexp", [&](auto&& args) -> Value {
			auto output = std::make_shared<RegexpExpression>(std::move(args[0].getYaramodString()));
			output->setType(Expression::Type::Regexp);
			output->setTokenStream(currentTokenStream());
			return output;
		})
		;// end of primary_expression

	_parser.rule("identifier") // Expression::Ptr
		.production("ID", [&](auto&& args) -> Value {
			TokenIt symbol_token = args[0].getTokenIt();
			auto symbol = findSymbol(symbol_token->getString());
			if (!symbol)
			{
				if (!incompleteMode())
					error_handle(args[0].getTokenIt()->getLocation(), "Unrecognized identifier '" + args[0].getTokenIt()->getPureText() + "' referenced");
				else
					symbol = std::make_shared<Symbol>(Symbol::Type::Undefined, symbol_token->getString(), ExpressionType::Undefined);
			}
			symbol_token->setValue(symbol);
			auto output = std::make_shared<IdExpression>(symbol_token);
			output->setType(symbol->getDataType());
			output->setTokenStream(currentTokenStream());
			return output;
		})
		.production("identifier", "DOT", "ID", [&](auto&& args) -> Value {
			const auto& expr = args[0].getExpression();
			if (!expr->isObject())
			{
				if (!incompleteMode() || !expr->isUndefined())
					error_handle((--args[1].getTokenIt())->getLocation(), "Identifier '" + expr->getText() + "' is not an object");
				else
				{
					auto parentExpr = std::static_pointer_cast<IdExpression>(expr);
					const auto& parentTokenText = parentExpr->getSymbolToken()->getText();
					parentExpr->setSymbol(std::make_shared<StructureSymbol>(parentTokenText));
				}
			}

			auto parentSymbol = std::static_pointer_cast<IdExpression>(expr)->getSymbol();
			while (parentSymbol->isReference())
				parentSymbol = std::static_pointer_cast<ReferenceSymbol>(parentSymbol)->getSymbol();
			if (!parentSymbol->isStructure())
			{
				assert(!incompleteMode() || !expr->isUndefined());
				error_handle((--args[1].getTokenIt())->getLocation(), "Identifier '" + parentSymbol->getName() + "' is not a structure");
			}
			auto structParentSymbol = std::static_pointer_cast<StructureSymbol>(parentSymbol);

			TokenIt symbol_token = args[2].getTokenIt();
			auto attr = structParentSymbol->getAttribute(symbol_token->getString());
			if (!attr)
			{
				if (!incompleteMode())
					error_handle(args[2].getTokenIt()->getLocation(), "Unrecognized identifier '" + symbol_token->getString() + "' referenced");
				else
				{
					bool inserted = structParentSymbol->addAttribute(std::make_shared<Symbol>(Symbol::Type::Undefined, symbol_token->getString(), ExpressionType::Undefined));
					attr = structParentSymbol->getAttribute(symbol_token->getString());
					assert(inserted && attr);
				}
			}

			auto symbol = attr.value();
			symbol_token->setValue(symbol);
			symbol_token->setType(symbol->getTokenType());
			auto output = std::make_shared<StructAccessExpression>(std::move(expr), args[1].getTokenIt(), symbol_token);
			output->setType(symbol->getDataType());
			output->setTokenStream(currentTokenStream());
			return output;
		})
		.production("identifier", "LSQB", "primary_expression", "RSQB", [&](auto&& args) -> Value {
			const auto& expr = args[0].getExpression();
			if (!expr->isObject())
			{
				if (!incompleteMode() || !expr->isUndefined())
					error_handle((--args[1].getTokenIt())->getLocation(), "Identifier '" + expr->getText() + "' is not an object");
				else
					expr->setType(ExpressionType::Object);
			}
			std::shared_ptr<Symbol> parentSymbol = std::static_pointer_cast<const IdExpression>(expr)->getSymbol();
			assert(parentSymbol);

			while (parentSymbol->isReference())
				parentSymbol = std::static_pointer_cast<const ReferenceSymbol>(parentSymbol)->getSymbol();

			if (!parentSymbol->isArray() && !parentSymbol->isDictionary())
			{
				const auto& parentSymbolName = parentSymbol->getName();
				if (!incompleteMode() || !parentSymbol->isUndefined())
					error_handle((--args[1].getTokenIt())->getLocation(), "Identifier '" + parentSymbolName + "' is not an array nor dictionary");
				else
					parentSymbol = std::make_shared<ArraySymbol>(parentSymbolName, ExpressionType::Undefined);
			}

			std::shared_ptr<const IterableSymbol> iterParentSymbol = std::static_pointer_cast<const IterableSymbol>(parentSymbol);

			std::shared_ptr<Symbol> arraySymbol;
			if (iterParentSymbol->isStructured())
				arraySymbol = iterParentSymbol->getStructuredElementType();
			else
				arraySymbol = std::make_shared<ValueSymbol>(expr->getText(), iterParentSymbol->getElementType());
			auto output = std::make_shared<ArrayAccessExpression>(arraySymbol, std::move(expr), args[1].getTokenIt(), std::move(args[2].getExpression()), args[3].getTokenIt());

			output->setType(iterParentSymbol->getElementType());
			output->setTokenStream(currentTokenStream());
			return output;
		})
		.production("identifier", "LP", "arguments", "RP", [&](auto&& args) -> Value {
			const auto& expr = args[0].getExpression();
			if (!expr->isObject())
			{
				if (!incompleteMode() || !expr->isUndefined())
					error_handle((--args[1].getTokenIt())->getLocation(), "Identifier '" + expr->getText() + "' is not an object");
				else
					expr->setType(ExpressionType::Object);
			}
			auto parentExpr = std::static_pointer_cast<IdExpression>(expr);
			auto parentSymbol = parentExpr->getSymbol();
			std::vector<Expression::Type> argTypes;
			auto arguments = std::move(args[2].getMultipleExpressions());

			while (parentSymbol->isReference())
				parentSymbol = std::static_pointer_cast<const ReferenceSymbol>(parentSymbol)->getSymbol();
				
			if (!parentSymbol->isFunction())
			{
				if (!incompleteMode() || !parentSymbol->isUndefined())
					error_handle((--args[1].getTokenIt())->getLocation(), "Identifier '" + parentSymbol->getName() + "' is not a function");
				else
				{
					const auto& parentTokenText = parentExpr->getSymbolToken()->getText();
					std::vector<ExpressionType> type{ExpressionType::Undefined};
					std::for_each(arguments.begin(), arguments.end(),
						[&type](const Expression::Ptr& e)
						{
							type.push_back(e->getType());
						});
					parentExpr->setSymbol(std::make_shared<FunctionSymbol>(parentTokenText, type));
					parentExpr->getSymbolToken()->setType(TokenType::FUNCTION_SYMBOL);
					parentSymbol = parentExpr->getSymbol();
				}
			}

			auto funcParentSymbol = std::static_pointer_cast<const FunctionSymbol>(parentSymbol);

			// Make copy of just argument types because symbols are not aware of expressions
			std::for_each(arguments.begin(), arguments.end(),
				[&argTypes](const Expression::Ptr& e)
				{
					argTypes.push_back(e->getType());
				});

			if (!funcParentSymbol->overloadExists(argTypes))
			{
				if (!incompleteMode())
				{
					std::stringstream ss;
					ss << "Unexpected argument types for function " << funcParentSymbol->getName() << " ( ";
					std::for_each(arguments.begin(), arguments.end(),
						[&ss](const Expression::Ptr& e)
						{
							ss << e->getTypeString() << " ";
						});
					ss << ")" << std::endl;
					error_handle((--args[1].getTokenIt())->getLocation(), "No matching overload of function '" + funcParentSymbol->getName() + "' for these types of parameters:\n" + ss.str());
				}
			}

			auto output = std::make_shared<FunctionCallExpression>(std::move(expr), args[1].getTokenIt(), std::move(arguments), args[3].getTokenIt());
			output->setType(funcParentSymbol->getReturnType());
			output->setTokenStream(currentTokenStream());
			return output;
		})
		;

	_parser.rule("arguments") // vector<Expression::Ptr>
		.production("arguments", "COMMA", "expression", [](auto&& args) -> Value {
			auto output = std::move(args[0].getMultipleExpressions());
			output.push_back(std::move(args[2].getExpression()));
			return output;
		})
		.production("expression", [](auto&& args) -> Value {
			std::vector<Expression::Ptr> output;
			output.push_back(std::move(args[0].getExpression()));
			return output;
		})
		.production([](auto&&) -> Value {
			return std::vector<Expression::Ptr>{};
		})
		;

	_parser.rule("range") // Expression::Ptr
		.production("LP", "primary_expression", "RANGE", "primary_expression", "RP", [&](auto&& args) -> Value {
			auto left = args[1].getExpression();
			auto right = args[3].getExpression();
			if (!left->isInt())
				error_handle(args[2].getTokenIt()->getLocation(), "operator '..' expects integer as lower bound of the interval");
			if (!right->isInt())
				error_handle(args[2].getTokenIt()->getLocation(), "operator '..' expects integer as upper bound of the interval");
			auto output = std::make_shared<RangeExpression>(args[0].getTokenIt(), std::move(left), args[2].getTokenIt(), std::move(right), args[4].getTokenIt());
			output->setTokenStream(currentTokenStream());
			return output;
		})
		;

	_parser.rule("for_expression") // Expression::Ptr
		.production("primary_expression", [](auto&& args) -> Value { return std::move(args[0]); })
		.production("ALL", [&](auto&& args) -> Value { return Value(std::make_shared<AllExpression>(currentTokenStream(), args[0].getTokenIt())); })
		.production("ANY", [&](auto&& args) -> Value { return Value(std::make_shared<AnyExpression>(currentTokenStream(), args[0].getTokenIt())); })
		.production("NONE", [&](auto&& args) -> Value { return Value(std::make_shared<NoneExpression>(currentTokenStream(), args[0].getTokenIt())); })
		;

	_parser.rule("integer_set") // Expression::Ptr
		.production("LP", "integer_enumeration", "RP", [&](auto&& args) -> Value {
			auto lp = args[0].getTokenIt();
			auto rp = args[2].getTokenIt();
			lp->setType(TokenType::LP_ENUMERATION);
			rp->setType(TokenType::RP_ENUMERATION);
			auto output = std::make_shared<SetExpression>(lp, std::move(args[1].getMultipleExpressions()), rp);
			output->setTokenStream(currentTokenStream());
			return output;
		})
		.production("range", [](auto&& args) -> Value {
			return std::move(args[0]);
		})
		;

	_parser.rule("integer_enumeration") // vector<Expression::Ptr>
		.production("primary_expression", [&](auto&& args) -> Value {
			auto expr = args[0].getExpression();
			if (!expr->isInt())
				error_handle(currentFileContext()->getLocation(), "integer set expects integer type");
			return std::vector<Expression::Ptr>{std::move(expr)};
		})
		.production("integer_enumeration", "COMMA", "primary_expression", [&](auto&& args) -> Value {
			auto expr = args[2].getExpression();
			if (!expr->isInt())
				error_handle(currentFileContext()->getLocation(), "integer set expects integer type");
			auto output = std::move(args[0].getMultipleExpressions());
			output.push_back(std::move(expr));
			return output;
		})
		;

	_parser.rule("string_set") // Expression::Ptr
		.production("LP", "string_enumeration", "RP", [&](auto&& args) -> Value {
			TokenIt lp = args[0].getTokenIt();
			lp->setType(TokenType::LP_ENUMERATION);
			TokenIt rp = args[2].getTokenIt();
			rp->setType(TokenType::RP_ENUMERATION);
			auto output = std::make_shared<SetExpression>(lp, std::move(args[1].getMultipleExpressions()), rp);
			output->setTokenStream(currentTokenStream());
			return output;
		})
		.production("THEM", [&](auto&& args) -> Value {
			return std::make_shared<ThemExpression>(currentTokenStream(), args[0].getTokenIt());
		})
		;

	_parser.rule("string_enumeration") // vector<Expression::Ptr>
		.production("string_enumeration_item", [&](auto&& args) -> Value {
			return std::vector<Expression::Ptr>{std::move(args[0].getExpression())};
		})
		.production("string_enumeration", "COMMA", "string_enumeration_item", [&](auto&& args) -> Value {
			auto output = std::move(args[0].getMultipleExpressions());
			output.push_back(std::move(args[2].getExpression()));
			return output;
		})
		;

	_parser.rule("string_enumeration_item") // Expression::Ptr
		.production("STRING_ID", [&](auto&& args) -> Value {
			TokenIt id = args[0].getTokenIt();
			if (!stringExists(id->getPureText()))
				error_handle(id->getLocation(), "Reference to undefined string '" + id->getPureText() + "'");
			if (id->getString().size() > 1)
				id->setValue(findStringDefinition(id->getString()));
			auto output = std::make_shared<StringExpression>(id);
			output->setTokenStream(currentTokenStream());
			return output;
		})
		.production("STRING_ID_WILDCARD", [&](auto&& args) -> Value {
			TokenIt id = args[0].getTokenIt();
			if (!stringExists(id->getPureText()))
				error_handle(id->getLocation(), "No string matched with wildcard '" + id->getPureText() + "'");
			auto output = std::make_shared<StringWildcardExpression>(id);
			output->setTokenStream(currentTokenStream());
			return output;
		})
		;

	_parser.rule("rule_set") // Expression::Ptr
		.production("LP", "rule_enumeration", "RP", [&](auto&& args) -> Value {
			TokenIt lp = args[0].getTokenIt();
			lp->setType(TokenType::LP_ENUMERATION);
			TokenIt rp = args[2].getTokenIt();
			rp->setType(TokenType::RP_ENUMERATION);
			auto output = std::make_shared<SetExpression>(lp, std::move(args[1].getMultipleExpressions()), rp);
			output->setTokenStream(currentTokenStream());
			return output;
		})
		;

	_parser.rule("rule_enumeration") // vector<Expression::Ptr>
		.production("rule_enumeration_item", [&](auto&& args) -> Value {
			return std::vector<Expression::Ptr>{std::move(args[0].getExpression())};
		})
		.production("rule_enumeration", "COMMA", "rule_enumeration_item", [&](auto&& args) -> Value {
			auto output = std::move(args[0].getMultipleExpressions());
			output.push_back(std::move(args[2].getExpression()));
			return output;
		})
		;

	_parser.rule("rule_enumeration_item") // Expression::Ptr
		.production("ID", [&](auto&& args) -> Value {
			TokenIt id = args[0].getTokenIt();
			if (!ruleExists(id->getPureText()))
				error_handle(id->getLocation(), "Reference to undefined rule '" + id->getPureText() + "'");

			auto symbol = findSymbol(id->getString());
			if (!symbol)
			{
				if (!incompleteMode())
					error_handle(args[0].getTokenIt()->getLocation(), "Unrecognized identifier '" + args[0].getTokenIt()->getPureText() + "' referenced");
				else
					symbol = std::make_shared<Symbol>(Symbol::Type::Undefined, id->getString(), ExpressionType::Undefined);
			}

			id->setValue(symbol);
			auto output = std::make_shared<IdExpression>(id);
			output->setType(symbol->getDataType());
			output->setTokenStream(currentTokenStream());
			return output;
		})
		.production("ID", "MULTIPLY", [&](auto&& args) -> Value {
			TokenIt id = args[0].getTokenIt();
			TokenIt wildcard = args[1].getTokenIt();
			id->setType(TokenType::ID_WILDCARD);
			wildcard->setType(TokenType::ID_WILDCARD);

			if (!incompleteMode() && !ruleWithPrefixExists(id->getPureText()))
				error_handle(id->getLocation(), "No rule matched with wildcard '" + id->getPureText() + "*'");

			auto output = std::make_shared<IdWildcardExpression>(id, wildcard);
			output->setTokenStream(currentTokenStream());
			return output;
		})
		;

	if (_features & Features::AvastOnly)
	{
		_parser.rule("expression_iterable") // shared_ptr<IterableExpression>
			.production("LSQB", "expression_enumeration", "RSQB", [&](auto&& args) -> Value {
				TokenIt lsqb = args[0].getTokenIt();
				lsqb->setType(TokenType::LSQB_ENUMERATION);
				TokenIt rsqb = args[2].getTokenIt();
				rsqb->setType(TokenType::RSQB_ENUMERATION);
				auto output = std::make_shared<IterableExpression>(lsqb, std::move(args[1].getMultipleExpressions()), rsqb);
				output->setTokenStream(currentTokenStream());
				return output;
			})
			;

		_parser.rule("expression_enumeration") // vector<Expression::Ptr>
			.production("expression", [&](auto&& args) -> Value {
				auto expression = args[0].getExpression();
				auto output = std::vector<Expression::Ptr>{std::move(expression)};
				output.front()->setTokenStream(currentTokenStream());
				return output;
			})
			.production("expression_enumeration", "COMMA", "expression", [&](auto&& args) -> Value {
				auto expression = args[2].getExpression();
				auto output = std::move(args[0].getMultipleExpressions());
				output.push_back(std::move(expression));
				output.back()->setTokenStream(currentTokenStream());
				return output;
			})
			;
	}
}

void ParserDriver::enter_state(const std::string& state)
{
	_parser.enter_tokenizer_state(state);
}

void ParserDriver::initialize()
{
	defineTokens();
	defineGrammar();
	_parser.set_start_symbol("rules");

	auto report = _parser.prepare();
	// Uncomment for advanced debugging with HtmlReport:
	// pog::HtmlReport html(_parser);
	// html.save("html_index.html");
	if (!report)
	{
		// Uncomment for debugging:
		// fmt::print("{}\n", report.to_string());
		throw YaramodError("Error: Parser initialization failed");
	}

	_valid = true;
}

/**
 * Constructor.
 *
 * @param moduleDirectory determines a directory for additional YARA modules to be added
 * @param features determines iff we want to use aditional Avast-specific symbols or VirusTotal-specific symbols in the imported modules
 */
ParserDriver::ParserDriver(Features features, const std::string& moduleDirectory)
	: _strLiteral(), _indent(), _comment(), _regexpClass(), _parser(), _sectionStrings(false),
	_escapedContent(false), _mode(ParserMode::Regular), _features(features),
	_modules(std::make_shared<ModulePool>(features, moduleDirectory)),
	_fileContexts(), _comments(), _includedFiles(), _includedFilesCache(), _valid(false),
	_file(), _currentStrings(), _stringLoop(false), _localSymbols(), _lastRuleLocation(),
	_lastRuleTokenStream(), _anonStringCounter(0)
{
	initialize();
}

ParserDriver::ParserDriver(Features features, const std::shared_ptr<ModulePool>& modulePool)
	: _strLiteral(), _indent(), _comment(), _regexpClass(), _parser(), _sectionStrings(false),
	_escapedContent(false), _mode(ParserMode::Regular), _features(features), _modules(modulePool),
	_fileContexts(), _comments(), _includedFiles(), _includedFilesCache(), _valid(false),
	_file(), _currentStrings(), _stringLoop(false), _localSymbols(), _lastRuleLocation(),
	_lastRuleTokenStream(), _anonStringCounter(0)
{
	initialize();
}

/**
 * Returns the result of parsing. The parsed YARA file.
 *
 * @return Parsed YARA file.
 */
YaraFile&& ParserDriver::getParsedFile()
{
	return std::move(_file);
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
 * Returns ModulePool used in the parser, which gives information on which modules are available.
 *
 * @return Used ModulePool
 */
std::map<std::string, Module*> ParserDriver::getModules() const
{
	return _modules->getModules();
}

bool ParserDriver::parse(std::istream& stream, ParserMode parserMode)
{
	if (!prepareParser(parserMode))
		return false;

	_fileContexts.emplace_back(&stream);
	_file = YaraFile(currentFileContext()->getTokenStream(), _features);
	try {
		auto output = parseImpl();
		return output;
	} catch (const ParserError& e) {
		if (!incompleteMode())
			throw e;
		else
			return true;
	}
}

bool ParserDriver::parse(const std::string& filePath, ParserMode parserMode)
{
	if (!prepareParser(parserMode))
		return false;

	if (includeFileImpl(filePath) != IncludeResult::Included)
		return false;

	_file = YaraFile(currentFileContext()->getTokenStream(), _features);
	return parseImpl();
}

bool ParserDriver::prepareParser(ParserMode parserMode)
{
	reset(parserMode);
	return true;
}

/**
 * Parses the input stream or file.
 *
 * @return @c true if parsing succeeded, otherwise @c false.
 */
bool ParserDriver::parseImpl()
{
	try
	{
		auto result = _parser.parse(*currentFileContext()->getStream());
		if (!result)
			throw YaramodError("Error: Parser failed to parse input.");
		return result.has_value();
	}
	catch (const pog::SyntaxError& err)
	{
		error_handle(!_fileContexts.empty() ? currentFileContext()->getLocation() : _errorLocation, err.what());
		return false;
	}
}

void ParserDriver::reset(ParserMode parserMode)
{
	_mode = parserMode;

	_strLiteral.clear();
	_indent.clear();
	_comment.clear();
	_regexpClass.clear();
	_sectionStrings = false;

	_fileContexts.clear();
	_comments.clear();
	_includedFiles.clear();
	_includedFilesCache.clear();
	_valid = true;
	_currentStrings = std::weak_ptr<Rule::StringsTrie>();
	_stringLoop = false;
	_localSymbols.clear();
	_lastRuleLocation.reset();
	_lastRuleTokenStream.reset();
	_anonStringCounter = 0;
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
 * Includes file into input stream as it would be in place of @c include directive.
 *
 * @param includePath Path of file to include.
 *
 * @return @c true if include succeeded, otherwise @c false.
 */
bool ParserDriver::includeFile(const std::string& includePath, const std::shared_ptr<TokenStream>& tokenStream)
{
	auto totalPath = includePath;
	if (pathIsRelative(includePath))
	{
		// We are not running ParserDriver from file input, just from some unnamed istream, therefore we need to forbid relative includes from
		// the top of the istream hierarchy
		if (currentFileContext()->isUnnamed())
			return false;

		// Take the topmost file path from the stack.
		// This allows us to nest includes forming hierarchy of included files.
		totalPath = absolutePath(joinPaths(parentPath(currentFileContext()->getLocation().getFilePath()), includePath));
	}

	// If all the underlying mechanisms for including succeeded, push the stream on top of input stack
	// Push input stream only if the file wasn't already included
	auto result = includeFileImpl(totalPath, tokenStream);
	if (result == IncludeResult::Included)
		_parser.push_input_stream(*_includedFiles.back());

	return result != IncludeResult::Error;
}

/**
 * Ends the include of the currently included file. This should normally happen when end-of-file is reached.
 * End of include may fail if there are no more files to pop from include stack.
 *
 * @return @c true if end of include succeeded, otherwise @c false.
 */
bool ParserDriver::includeEnd()
{
	_parser.pop_input_stream();
	if (!_fileContexts.empty())
	{
		popFileContext();
		if (!_includedFiles.empty())
			_includedFiles.pop_back(); // Pop _includedFiles to release file descriptor
	}
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
	return _file.hasRule(name);
}

/**
 * Returns whether rule with given prefix already exists.
 *
 * @param prefix Prefix of the rule.
 *
 * @return @c true if exists, @c false otherwise.
 */
bool ParserDriver::ruleWithPrefixExists(const std::string& prefix) const
{
	return _file.hasRuleWithPrefix(prefix);
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
	rule->setLocation(_lastRuleLocation);

	if (ruleExists(rule->getName()))
		throw ParserError("Error: Redefinition of rule " + rule->getName());

	_file.addRule(std::move(rule));
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

const Literal* ParserDriver::findStringDefinition(const std::string& id) const
{
	auto currentStrings = _currentStrings.lock();
	std::shared_ptr<String> string;
	if (currentStrings && currentStrings->find(id, string))
		return string->getIdentifierTokenIt();
	else
		return nullptr;
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

IncludeResult ParserDriver::includeFileImpl(const std::string& includePath, std::optional<std::shared_ptr<TokenStream>> tokenStream)
{
	if (_mode == ParserMode::IncludeGuarded && isAlreadyIncluded(includePath))
		return IncludeResult::AlreadyIncluded;

	// We need to allocate ifstreams dynamically because they are not copyable and we need to store them
	// in vector to prolong their lifetime because of flex.
	auto fileStream = std::make_shared<std::ifstream>(includePath, std::ios::binary);
	if (!fileStream->is_open())
		return IncludeResult::Error;

	_includedFiles.push_back(std::move(fileStream));
	if (tokenStream)
		_fileContexts.emplace_back(includePath, _includedFiles.back().get(), tokenStream.value());
	else
		_fileContexts.emplace_back(includePath, _includedFiles.back().get());
	_includedFilesCache.emplace(absolutePath(includePath));

	return IncludeResult::Included;
}

void ParserDriver::checkStringModifier(const std::vector<std::shared_ptr<StringModifier>>& previousMods, const std::shared_ptr<StringModifier>& newMod)
{
	using T = StringModifier::Type;
	// Table of invalid combinations of string modifiers; see
	// https://yara.readthedocs.io/en/latest/writingrules.html#string-modifier-summary
	const static std::map<T, std::vector<T>> invalidCombinationsTable = {
		{T::Ascii, {}},
		{T::Wide, {}},
		{T::Nocase, {T::Xor, T::Base64, T::Base64Wide}},
		{T::Fullword, {T::Base64, T::Base64Wide}},
		{T::Private, {}},
		{T::Xor, {T::Nocase, T::Base64, T::Base64Wide}},
		{T::Base64, {T::Nocase, T::Fullword, T::Xor}},
		{T::Base64Wide, {T::Nocase, T::Fullword, T::Xor}}
	};
	auto newModType = newMod->getType();
	auto forbiddenMods = invalidCombinationsTable.find(newModType)->second;
	for (const auto& previousMod: previousMods)
	{
		auto previousModType = previousMod->getType();
		if (std::find(forbiddenMods.begin(), forbiddenMods.end(), previousModType) != forbiddenMods.end())
			error_handle(newMod->getTokenRange().first->getLocation(), "Invalid combination of string modifiers (" + previousMod->getName() + ", " + newMod->getName() + ")");

		if (newModType == previousModType)
			error_handle(newMod->getTokenRange().first->getLocation(), "Duplicated modifier " + newMod->getName());

		if ((newModType == T::Base64 && previousModType == T::Base64Wide &&
			std::static_pointer_cast<Base64StringModifier>(newMod)->getAlphabet() != std::static_pointer_cast<Base64WideStringModifier>(previousMod)->getAlphabet()) ||
			(newModType == T::Base64Wide && previousModType == T::Base64 &&
			std::static_pointer_cast<Base64WideStringModifier>(newMod)->getAlphabet() != std::static_pointer_cast<Base64StringModifier>(previousMod)->getAlphabet()))
		{
			error_handle(newMod->getTokenRange().first->getLocation(), "Can not specify multiple alphabets for base64 modifiers");
		}
	}
}

Rule ParserDriver::createCommonRule(std::vector<yaramod::Value>& args)
{
	std::optional<TokenIt> mod_private = {};
	std::optional<TokenIt> mod_global = {};
	const std::vector<TokenIt> mods = std::move(args[0].getMultipleTokenIt());
	for (const auto &token: mods)
	{
		if (token->getType() == TokenType::GLOBAL)
		{
			if (mod_global.has_value())
				error_handle(token->getLocation(), "Duplicated global rule modifier");
			mod_global = token;
		}
		else if (token->getType() == TokenType::PRIVATE)
		{
			if (mod_private.has_value())
				error_handle(token->getLocation(), "Duplicated private rule modifier");
			mod_private = token;
		}
	}
	TokenIt name = args[3].getTokenIt();
	const std::vector<TokenIt> tags = std::move(args[5].getMultipleTokenIt());
	args[6].getTokenIt()->setType(TokenType::RULE_BEGIN);
	std::vector<Meta> metas = std::move(args[7].getMetas());
	return Rule(_lastRuleTokenStream, name, std::move(mods),
				std::move(metas), std::make_shared<Rule::StringsTrie>(), std::vector<Variable>(), NULL, std::move(tags));
}

} //namespace yaramod
