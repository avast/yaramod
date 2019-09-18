/**
 * @file src/parser/parser_driver.cpp
 * @brief Implementation of class ParserDriver.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "yaramod/parser/parser_driver.h"
#include "yaramod/utils/filesystem.h"
#include "yaramod/types/expressions.h"

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
	// _parser.set_start_symbol("testing_delete_this");
	_parser.set_start_symbol("rules");
	bool prepared = prepareParser();
	assert( prepared && "Parser initialization failed");
}

template<typename... Args>
TokenIt PogParser::emplace_back(Args&&... args)
{
	return _driver.currentStream()->emplace_back(args...);
}

void print(const std::string& symbol, const std::string_view& value)
{
	// std::cerr << symbol << ": '" << std::string{value} << "'" << std::endl;
}
void print(const std::string& symbol, const std::string& value)
{
	// std::cerr << symbol << ": '" << value << "'" << std::endl;
}

void PogParser::defineTokens()
{
	_parser.token("\n").action( [&](std::string_view str) -> Value { return emplace_back(NEW_LINE, std::string{str}); });
	_parser.token("[ \t\r]+"); // spaces, tabulators, carrige-returns

	_parser.token(R"(\.\.)").symbol("RANGE").action( [&](std::string_view str) 	-> Value { return emplace_back( RANGE, std::string{str} ); } );
	_parser.token(R"(\.)").symbol("DOT").action( [&](std::string_view str) 			-> Value { return emplace_back( DOT, std::string{str} ); } );
	_parser.token("<").symbol("LT").action( [&](std::string_view str) 				-> Value { return emplace_back( LT, std::string{str} ); } );
	_parser.token(">").symbol("GT").action( [&](std::string_view str) 				-> Value { return emplace_back( GT, std::string{str} ); } );
	_parser.token("<=").symbol("LE").action( [&](std::string_view str) 				-> Value { return emplace_back( LE, std::string{str} ); } );
	_parser.token(">=").symbol("GE").action( [&](std::string_view str) 				-> Value { return emplace_back( GE, std::string{str} ); } );
	_parser.token("==").symbol("EQ").action( [&](std::string_view str) 				-> Value { return emplace_back( EQ, std::string{str} ); } );
	_parser.token("!=").symbol("NEQ").action( [&](std::string_view str) 				-> Value { return emplace_back( NEQ, std::string{str} ); } );
	_parser.token("<<").symbol("SHIFT_LEFT").action( [&](std::string_view str) 	-> Value { return emplace_back( SHIFT_LEFT, std::string{str} ); } );
	_parser.token(">>").symbol("SHIFT_RIGHT").action( [&](std::string_view str) 	-> Value { return emplace_back( SHIFT_RIGHT, std::string{str} ); } );
	_parser.token(R"(-)").symbol("MINUS").action( [&](std::string_view str) 		-> Value { return emplace_back(MINUS, std::string{str}); } )
		.precedence(1, pog::Associativity::Left);
	_parser.token(R"(\+)").symbol("PLUS").action( [&](std::string_view str) 		-> Value { return emplace_back(PLUS, std::string{str}); } )
		.precedence(1, pog::Associativity::Left);
	_parser.token(R"(\*)").symbol("MULTIPLY").action( [&](std::string_view str)	-> Value { return emplace_back(MULTIPLY, std::string{str}); } )
		.precedence(2, pog::Associativity::Left);
	_parser.token(R"(\\)").symbol("DIVIDE").action( [&](std::string_view str) 		-> Value { return emplace_back(DIVIDE, std::string{str}); } )
		.precedence(2, pog::Associativity::Left);
	_parser.token(R"(\%)").symbol("MODULO").action( [&](std::string_view str) 		-> Value { return emplace_back(MODULO, std::string{str}); } );
	_parser.token(R"(\^)").symbol("BITWISE_XOR").action( [&](std::string_view str) -> Value { return emplace_back(BITWISE_XOR, std::string{str}); } );
	_parser.token(R"(\&)").symbol("BITWISE_AND").action( [&](std::string_view str) -> Value { return emplace_back(BITWISE_AND, std::string{str}); } );
	_parser.token(R"(\|)").symbol("BITWISE_OR").action( [&](std::string_view str) -> Value { return emplace_back(BITWISE_OR, std::string{str}); } );
	_parser.token(R"(\~)").symbol("BITWISE_NOT").action( [&](std::string_view str) -> Value { return emplace_back(BITWISE_NOT, std::string{str}); } );
	_parser.token("\\(").symbol("LP").action( [&](std::string_view str) -> Value { return emplace_back(LP, std::string{str}); } );
	_parser.token("\\)").symbol("RP").action( [&](std::string_view str) -> Value { return emplace_back(RP, std::string{str}); } );
	// _parser.token("\\{").symbol("LCB").action( [&](std::string_view str) -> Value { return std::string{str}; } );
	// _parser.token("\\}").symbol("RCB").action( [&](std::string_view str) -> Value { return std::string{str}; } );
	_parser.token("\\{").symbol("LCB").action( [&](std::string_view str) -> Value { print("LCB", str); return emplace_back(LCB, std::string{str}); } );
	_parser.token("\\}").symbol("RCB").action( [&](std::string_view str) -> Value { print("RCB", str); return emplace_back(RCB, std::string{str}); } );
	_parser.token("\\[").symbol("LSQB").action( [&](std::string_view str) -> Value { return emplace_back( LSQB, std::string{str} ); } );
	_parser.token("\\]").symbol("RSQB").action( [&](std::string_view str) -> Value { return emplace_back( RSQB, std::string{str} ); } );
	_parser.token("=").symbol("ASSIGN").action( [&](std::string_view str) -> Value { return emplace_back( ASSIGN, std::string{str} ); } );
	_parser.token(":").symbol("COLON").action( [&](std::string_view str) -> Value { return emplace_back( COLON, std::string{str} ); } );
	_parser.token(",").symbol("COMMA").action( [&](std::string_view str) -> Value { return emplace_back( COMMA, std::string{str} ); } );
	_parser.token("/").symbol("SLASH").action( [&](std::string_view str) -> Value { return std::string{str}; } );
	_parser.token("global").symbol("GLOBAL").action( [](std::string_view str) -> Value { return std::string{str}; } );
	_parser.token("private").symbol("PRIVATE").action( [](std::string_view str) -> Value { return std::string{str}; } );
	_parser.token("rule").symbol("RULE").action( [&](std::string_view str) -> Value { print("RULE", str); _driver.markStartOfRule(); return emplace_back( RULE, std::string{str} ); } );
	_parser.token("meta").symbol("META").action( [&](std::string_view str) -> Value { return emplace_back( META, std::string{str} ); } );
	_parser.token("strings").symbol("STRINGS").action( [&](std::string_view str) -> Value { return emplace_back( STRINGS, std::string{str} ); } );
	_parser.token("condition").symbol("CONDITION").action( [&](std::string_view str) -> Value { print("CONDITION", str); return emplace_back( CONDITION, std::string{str} ); } );
	_parser.token("ascii").symbol("ASCII").action( [&](std::string_view str) -> Value { return emplace_back( ASCII, std::string{str} ); } );
	_parser.token("nocase").symbol("NOCASE").action( [&](std::string_view str) -> Value { return emplace_back( NOCASE, std::string{str} ); } );
	_parser.token("wide").symbol("WIDE").action( [&](std::string_view str) -> Value { return emplace_back( WIDE, std::string{str} ); } );
	_parser.token("fullword").symbol("FULLWORD").action( [&](std::string_view str) -> Value { return emplace_back( FULLWORD, std::string{str} ); } );
	_parser.token("xor").symbol("XOR").action( [&](std::string_view str) -> Value { return emplace_back( XOR, std::string{str} ); } );
	_parser.token("true").symbol("BOOL_TRUE").action( [&](std::string_view) -> Value { return emplace_back( BOOL_TRUE, true ); } );
	_parser.token("false").symbol("BOOL_FALSE").action( [&](std::string_view) -> Value { return emplace_back( BOOL_FALSE, false ); } );
	_parser.token("import").symbol("IMPORT_KEYWORD").action( [&](std::string_view str) -> Value { return emplace_back( IMPORT_KEYWORD, std::string{str} ); } );
	_parser.token("not").symbol("NOT").action( [&](std::string_view str) -> Value { return emplace_back( NOT, std::string{str} ); } );
	_parser.token("and").symbol("AND").action( [&](std::string_view str) -> Value { return emplace_back( AND, std::string{str} ); } );
	_parser.token("or").symbol("OR").action( [&](std::string_view str) -> Value { return emplace_back( OR, std::string{str} ); } );
	_parser.token("all").symbol("ALL").action( [&](std::string_view str) -> Value { return emplace_back( ALL, std::string{str} ); } );
	_parser.token("any").symbol("ANY").action( [&](std::string_view str) -> Value { return emplace_back( ANY, std::string{str} ); } );
	_parser.token("of").symbol("OF").action( [&](std::string_view str) -> Value { return emplace_back( OF, std::string{str} ); } );
	_parser.token("them").symbol("THEM").action( [&](std::string_view str) -> Value { return emplace_back( THEM, std::string{str} ); } );
	_parser.token("for").symbol("FOR").action( [&](std::string_view str) -> Value { return emplace_back( FOR, std::string{str} ); } );
	_parser.token("entrypoint").symbol("ENTRYPOINT").action( [&](std::string_view str) -> Value { return emplace_back( ENTRYPOINT, std::string{str} ); } );
	_parser.token("op_at").symbol("AT").action( [&](std::string_view str) -> Value { return emplace_back( OP_AT, std::string{str} ); } );
	_parser.token("op_in").symbol("IN").action( [&](std::string_view str) -> Value { return emplace_back( OP_IN, std::string{str} ); } );
	_parser.token("filesize").symbol("FILESIZE").action( [&](std::string_view str) -> Value { return emplace_back( FILESIZE, std::string{str} ); } );
	_parser.token("contains").symbol("CONTAINS").action( [&](std::string_view str) -> Value { return emplace_back( CONTAINS, std::string{str} ); } );
	_parser.token("matches").symbol("MATCHES").action( [&](std::string_view str) -> Value { return emplace_back( MATCHES, std::string{str} ); } );
	_parser.token("include").symbol("INCLUDE_DIRECTIVE").action( [&](std::string_view str) -> Value { return emplace_back(INCLUDE_DIRECTIVE, std::string{str}); } );
	_parser.token(R"(\"(\\.|[^\\"])*\")").symbol("STRING_LITERAL").action( [&](std::string_view str) -> Value { return emplace_back(STRING_LITERAL, std::string{str}.substr(1, str.size()-2)); } );
	// _parser.token(R"(\"(\\.|[^\\"])*\")").symbol("STRING_LITERAL").action( [&](std::string_view str) -> Value { return emplace_back(std::string{str}); } );

	_parser.token(R"(0x[0-9a-fA-F]+)").symbol("INTEGER").action( [&](std::string_view str) -> Value {
		return emplace_back(INTEGER, std::stol(std::string{str}.substr(2), 0, 16), std::make_optional(std::string{str}) );
	} );
	// _parser.token(R"([0-9]+\.[0-9]+)").symbol("INTEGER").action( [&](std::string_view str) -> Value { return emplace_back(INTEGER, std::string{str}); } );
	_parser.token(R"([0-9]+KB)").symbol("INTEGER").action( [&](std::string_view str) -> Value {
		return emplace_back(INTEGER, 1000 * std::stol(std::string{str}), std::make_optional(std::string{str}));
	} );
	_parser.token(R"([0-9]+MB)").symbol("INTEGER").action( [&](std::string_view str) -> Value {
		return emplace_back(INTEGER, 1000000 * std::stol(std::string{str}), std::make_optional(std::string{str}));
	} );
	_parser.token(R"([0-9]+)").symbol("INTEGER").action( [&](std::string_view str) -> Value {
		return emplace_back(INTEGER, std::stol(std::string{str}), std::make_optional(std::string{str}));
	} );

	//like ({letter}|_)({letter}|{digit}|_)* in FLEX lexer:
	// _parser.token("[a-zA-Z_][a-zA-Z0-9_]*").symbol("ID").action( [](std::string_view str) -> Value { return std::string{str}; } );
	_parser.token("[a-zA-Z_][a-zA-Z0-9_]*").symbol("ID").action( [&](std::string_view str) -> Value { return emplace_back(ID, std::string{str}); } );
	_parser.token(R"(\$[a-zA-Z0-9]*)").symbol("STRING_ID").action( [&](std::string_view str) -> Value { return emplace_back(STRING_ID, std::string{str}); } );

	_parser.token("u?int(8|16|32)(be)?").symbol("INTEGER_FUNCTION").action( [&](std::string_view str) -> Value { return std::string{str}; } );

	// STRINGS
	_parser.token("\"").states("@default").enter_state("@str").action( [&](std::string_view) 	-> Value { _strLiteral.clear(); return {}; } );
	_parser.token("\t").states("@str").action( [&](std::string_view) 									-> Value { _strLiteral += '\t'; return {}; } );
	_parser.token("\n").states("@str").action( [&](std::string_view) 									-> Value { _strLiteral += '\n'; return {}; } );
	_parser.token(R"(\\x[0-9a-fA-F]{2})").states("@str").action( [&](std::string_view str)		-> Value {
		std::uint64_t num = 0;
		strToNum(std::string{str}, num, std::hex);
		_strLiteral += static_cast<char>(num);
		return {};
	} );
	_parser.token("\\\"").states("@str").action( [&](std::string_view) 								-> Value { _strLiteral += '\"'; return {}; } );
	_parser.token("\\\\").states("@str").action( [&](std::string_view) 								-> Value { _strLiteral += '\\'; return {}; } );
	_parser.token("\\.").states("@str").action( [&](std::string_view str)							-> Value {
		throw ParserError(std::string("Error at <TODO>: Unknown escape sequence \'" + std::string{str} + "\'"));
	} );
	_parser.token( R"(([^\\"])+)" ).states("@str").action( [&](std::string_view str)				-> Value { _strLiteral += std::string{str}; return {}; } );
	_parser.token("\"").states("@str").enter_state("@default").action( [&](std::string_view)	-> Value { return emplace_back(STRING_LITERAL, _strLiteral); } );


	_parser.end_token().action([](std::string_view str) -> Value { std::cout << "End of input" << std::string{str} << std::endl; return {}; });
}

void PogParser::defineGrammar()
{
	_parser.rule("rules")
		.production("rules", "rule"/*, [](auto&& args) 	-> Value	{ return std::move(args[0]); }*/ )
		.production("rules", "import"/*, [](auto&& args) 	-> Value { return std::move(args[0]); }*/ )
		// .production("rules", "END"/*, [](auto&& args) 		-> Value { return std::move(args[0]); }*/ )
		.production()
		;
	_parser.rule("import")
		.production("IMPORT_KEYWORD", "STRING_LITERAL", [&](auto&& args) -> Value {
			TokenIt import = args[1].getTokenIt();
			import->setType(IMPORT_MODULE);
			if(!_driver._file.addImport(import))
				error_handle("Unrecognized module '" + import->getString() + "' imported");
			return {};
		});

	_parser.rule("rule")
		.production("rule_mod", "RULE", "rule_name", "tags", "rule_begin", "metas", "strings", "condition", "rule_end", [&](auto&& args) -> Value {
			std::cout << "Matched 'rule'" << std::endl;
			TokenIt name = args[2].getTokenIt();
			if(_driver.ruleExists(name->getString()))
				error_handle("Rule already exists");
			std::optional<TokenIt> mod = std::move(args[0].getOptionalTokenIt());
			std::vector<Meta> metas = std::move(args[5].getMetas());
			std::shared_ptr<Rule::StringsTrie> strings = std::move(args[6].getStringsTrie());
			Expression::Ptr condition = std::move(args[7].getExpression()); //TODO fill it
			const std::vector<TokenIt> tags = std::move(args[3].getMultipleTokenIt());

			_driver.addRule(Rule(_driver.currentStream(), name, std::move(mod), std::move(metas), std::move(strings), std::move(condition), std::move(tags)));
			std::cout << "Made rule '" << name->getString() << "'" << std::endl;
			std::cout << "TokenStream: " << *_driver.currentStream() << std::endl;
			return {};
		});

	_parser.rule("rule_mod")
		.production("GLOBAL", [&](auto&&) -> Value { return emplace_back(GLOBAL, "global"); })
		.production("PRIVATE", [&](auto&&) -> Value { return emplace_back(PRIVATE, "private"); })
		.production([&](auto&&) -> Value { return Value(std::nullopt); })
		;
	_parser.rule("rule_name")
		.production("ID", [&](auto&& args) -> Value {
			args[0].getTokenIt()->setType(RULE_NAME);
			return args[0];
		});
	_parser.rule("tags")
		.production("COLON", "tag_list", [](auto&& args) -> Value {
			return std::move(args[1]);
		})
		.production([](auto&&) -> Value {
			return std::vector<TokenIt>();
		})
		;
	_parser.rule("tag_list")
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
	_parser.rule("rule_begin")
		.production("LCB", [&](auto&& args) -> Value {
			args[0].getTokenIt()->setType(RULE_BEGIN);
			return args[0];
		});
	_parser.rule("rule_end")
		.production("RCB", [&](auto&& args) -> Value {
			args[0].getTokenIt()->setType(RULE_END);
			return args[0];
		});

	_parser.rule("metas")
		.production("META", "COLON", "metas_body", [](auto&& args) -> Value { return std::move(args[2]); })
		.production([](auto&&) -> Value { return std::vector<yaramod::Meta>(); })
		;
		//Continue with following
	_parser.rule("metas_body")
		.production("metas_body", "ID", "ASSIGN", "literal", [&](auto&& args) -> Value {
			std::vector<Meta> body = std::move(args[0].getMetas());
			TokenIt key = args[1].getTokenIt();
			key->setType(META_KEY);
			//emplace_back(EQ, "=");
			TokenIt val = args[3].getTokenIt();
			val->setType(META_VALUE);
			body.emplace_back(key, val);
			return Value(std::move(body));
		})
		.production([](auto&&) -> Value { return std::vector<yaramod::Meta>(); })
		;

	_parser.rule("literal") //toto nebude typu literal ale TokenIt a vklada se uz v tokenizeru
		.production("STRING_LITERAL", [](auto&& args) -> Value { return args[0]; })
		.production("INTEGER", [](auto&& args) -> Value { return std::move(args[0]); })
		.production("boolean", [](auto&& args) -> Value { return args[0]; })
		;

	_parser.rule("boolean")
		.production("BOOL_TRUE", [](auto&& args) -> Value { return args[0]; })
		.production("BOOL_FALSE", [](auto&& args) -> Value { return args[0]; })
		;

	_parser.rule("strings")
		.production("STRINGS", "COLON", "strings_body", [](auto&& args) -> Value { return args[2]; })
		.production([&](auto&&) -> Value {
			auto strings = std::make_shared<Rule::StringsTrie>();
			_driver.setCurrentStrings(strings);
			return std::move(strings);
		})
		;
	_parser.rule("strings_body")
		.production("strings_body", "STRING_ID", "ASSIGN", "string", [&](auto&& args) -> Value {
			const std::string& id = args[1].getTokenIt()->getPureText(); std::cout << "id " << id << std::endl;
			const std::string& trieId = _driver.isAnonymousStringId(id) ? _driver.generateAnonymousStringPseudoId() : id;
			auto string = std::move(args[3].getYaramodString());
			string->setIdentifier(args[1].getTokenIt(), args[2].getTokenIt());
			auto strings = std::move(args[0].getStringsTrie());
			std::cout << "inserting string " << string->getText() << std::endl;
			if(!strings->insert(trieId, std::move(string)))
			{
				error_handle("Redefinition of string '" + trieId + "'");
			}
			return std::move(strings);
		})
		.production([&](auto&&) -> Value {
			auto strings = std::make_shared<Rule::StringsTrie>();
			_driver.setCurrentStrings(strings);
			return std::move(strings);
		})
		;
	_parser.rule("string") //TODO FIX
		.production("STRING_LITERAL", "string_mods", [&](auto&& args) -> Value {
			auto string = std::make_shared<PlainString>(_driver.currentStream(), std::move(args[0].getTokenIt()));
			std::pair<std::uint32_t, std::vector<TokenIt>> mods = std::move(args[1].getStringMods());
			string->setModifiers(mods.first, std::move(mods.second));
			return Value(std::move(string));
		})
		// .production() TODO
		;

	_parser.rule("string_mods")
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

	_parser.rule("condition")
		.production("CONDITION", "COLON", "expression", [](auto&& args) -> Value {
			std::cout << "Matched 'condition'" << std::endl;
			return std::move(args[2]);
		})
		;
	_parser.rule("expression")
		.production("boolean", [&](auto&& args) -> Value {
			std::cout << "Matched 'expression'" << std::endl;
			auto output = Value(std::move(std::make_shared<BoolLiteralExpression>(args[0].getTokenIt())));
			output.getExpression()->setType(Expression::Type::Bool);
			return std::move(output);
		}) //TODO add more
		;
}

bool PogParser::prepareParser()
{
	auto report = _parser.prepare();
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

void PogParser::parse()
{
	try
	{
		auto result = _parser.parse(*_input);
		std::cout << "parsing finished" << std::endl;
	   if (!result)
	   {
	      std::cerr << "Error" << std::endl;
	      return;
	   }
	}
	catch(const pog::SyntaxError& err)
	{
		std::cerr << err.what() << std::endl;
	}
}

/**
 * Constructor.
 *
 * @param filePath Input file path.
 * @param parserMode Parsing mode.
 */
ParserDriver::ParserDriver(const std::string& filePath, ParserMode parserMode) : _mode(parserMode), _lexer(*this), _parser(*this), _pog_parser(*this),
	_loc(nullptr), _valid(true), _filePath(), _inputFile(), _currentStrings(),
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
ParserDriver::ParserDriver(std::istream& input, ParserMode parserMode) : _mode(parserMode), _lexer(*this, &input), _parser(*this), _pog_parser(*this),
	_loc(nullptr),  _valid(true), _filePath(), _inputFile(), _currentStrings(),
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

	//BISON:
	//bool output = _parser.parse() == 0;
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
		_loc = _includedFileLocs.back();
		_includedFileLocs.pop_back();
	}

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

	_lexer.includeFile(includedFile.get());

	_pog_parser.setInput(includedFile.get());

	_tokenStreams.push(substream);
	_includedFiles.push_back(std::move(includedFile));
	_includedFileNames.push_back(includePath);
	_includedFileLocs.push_back(_loc);
	_includedFilesCache.emplace(absolutePath(includePath));

	// Reset location se we can keep track of line numbers in included files
	_loc.begin.initialize(_loc.begin.filename, 1, 1);
	_loc.end.initialize(_loc.end.filename, 1, 1);
	return true;
}

} //namespace yaramod
