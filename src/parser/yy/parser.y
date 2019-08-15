/**
 * @file src/parser/yy/parser.y
 * @brief Parser for YARA parser.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

%code requires {
#include <iterator>

#include "yaramod/types/expressions.h"
#include "yaramod/types/hex_string.h"
#include "yaramod/types/literal.h"
#include "yaramod/types/meta.h"
#include "yaramod/types/plain_string.h"
#include "yaramod/types/regexp.h"
#include "yaramod/types/rule.h"
#include "yaramod/utils/trie.h"

namespace yaramod {

class ParserDriver;


/**
 * Helper function to transfer char ('0' -- 'F') to uint8_t
 */
//uint8_t charToInt (char c)
//{
//	return ('A' <= std::toupper(c) && std::toupper(c) <= 'F') ? std::toupper(c) - 'A' + 10 : c - '0';
//}

// We need to provide alias to this type because since bison 3.2
// types are enclosed in YY_RVREF() macro. The comma in template
// parameter list is however parsed by preprocessor first and
// therefore the preprocessor thinks we are passing it 2 arguments.
// We then get error like this:
//
// error: too many arguments provided to function-like macro invocation
//
// See https://github.com/avast/yaramod/issues/11 for further information.
using RegexpRangePair = std::pair<nonstd::optional<std::uint64_t>, nonstd::optional<std::uint64_t>>;

}

// Uncomment for debugging
// See also other occurrences of 'debugging' in this file and constructor of ParserDriver to enable it
// #define YYDEBUG 1
}

%code top {
#include "yaramod/parser/parser_driver.h"

using namespace yaramod;

static yy::Parser::symbol_type yylex(ParserDriver& driver)
{
	return driver.getLexer().getNextToken();
}
}

%skeleton "lalr1.cc"
%require "3.0"

%define api.token.constructor
%define api.value.type variant
%define parse.assert
%locations
%error-verbose

%define api.namespace { yaramod::yy }
%define parser_class_name { Parser }
%parse-param { yaramod::ParserDriver& driver }
%lex-param { yaramod::ParserDriver& driver }

// Uncomment for debugging
// See also other occurrences of 'debugging' in this file and constructor of ParserDriver to enable it
%define parse.trace
%debug

%token END              "end of file"
%token RANGE            "integer range"
%token DOT              "."
%token LT               "<"
%token GT               ">"
%token LE               "<="
%token GE               ">="
%token EQ               "=="
%token NEQ              "!="
%token SHIFT_LEFT       "<<"
%token SHIFT_RIGHT      ">>"
%token MINUS            "-"
%token PLUS             "+"
%token MULTIPLY         "*"
%token DIVIDE           "\\"
%token MODULO           "%"
%token BITWISE_XOR      "^"
%token BITWISE_AND      "&"
%token BITWISE_OR       "|"
%token BITWISE_NOT      "~"
%token LP               "("
%token RP               ")"
%token LCB              "{"
%token RCB              "}"
%token ASSIGN           "="
%token COLON            ":"
%token COMMA            ","
%token PRIVATE          "private"
%token GLOBAL           "global"
%token RULE             "rule"
%token META             "meta"
%token STRINGS          "strings"
%token CONDITION        "condition"
%token ASCII            "ascii"
%token NOCASE           "nocase"
%token WIDE             "wide"
%token FULLWORD         "fullword"
%token XOR              "xor"
%token BOOL_TRUE        "true"
%token BOOL_FALSE       "false"
%token IMPORT_KEYWORD    "import"
%token NOT              "not"
%token AND              "and"
%token OR               "or"
%token ALL              "all"
%token ANY              "any"
%token OF               "of"
%token THEM             "them"
%token FOR              "for"
%token ENTRYPOINT       "entrypoint"
%token OP_AT            "at"
%token OP_IN            "in"
%token FILESIZE         "filesize"
%token CONTAINS         "contains"
%token MATCHES          "matches"
%token <std::string> SLASH              		"/"
%token <std::string> STRING_LITERAL				"string literal"
%token <std::string> INTEGER           		"integer"
%token <std::string> DOUBLE             		"float"
%token <std::string> STRING_ID          		"string identifier"
%token <std::string> STRING_ID_WILDCARD 		"string wildcard"
%token <yaramod::TokenIt> STRING_LENGTH   	"string length"
%token <yaramod::TokenIt> STRING_OFFSET     	"string offset"
%token <yaramod::TokenIt> STRING_COUNT      	"string count"
%token <std::string> ID                 		"identifier"
%token <std::string> INTEGER_FUNCTION   		"fixed-width integer function"
//%token <std::string> STRING_META        	::

%token HEX_OR                      "hex string |"
%token LSQB                        "hex string ["
%token RSQB                        "hex string ]"
%token HEX_WILDCARD                "hex string ?"
%token DASH                        "hex string -"
%token <std::string> HEX_NIBBLE   "hex string nibble"
//%token <std::uint8_t> HEX_NIBBLE   "hex string nibble"
%token <std::uint64_t> HEX_INTEGER "hex string integer"

%token REGEXP_OR                                "regexp |"
%token REGEXP_ITER                              "regexp *"
%token REGEXP_PITER                             "regexp +"
%token REGEXP_OPTIONAL                          "regexp ?"
%token REGEXP_START_OF_LINE                     "regexp ^"
%token REGEXP_END_OF_LINE                       "regexp $"
%token REGEXP_ANY_CHAR                          "regexp ."
%token REGEXP_WORD_CHAR                         "regexp \\w"
%token REGEXP_NON_WORD_CHAR                     "regexp \\W"
%token REGEXP_SPACE                             "regexp \\s"
%token REGEXP_NON_SPACE                         "regexp \\S"
%token REGEXP_DIGIT                             "regexp \\d"
%token REGEXP_NON_DIGIT                         "regexp \\D"
%token REGEXP_WORD_BOUNDARY                     "regexp \\b"
%token REGEXP_NON_WORD_BOUNDARY                 "regexp \\B"
%token <std::string> REGEXP_CHAR                "regexp character"
%token <yaramod::RegexpRangePair> REGEXP_RANGE  "regexp range"
%token <std::string> REGEXP_CLASS               "regexp class"

%type <std::optional<yaramod::TokenIt>> rule_mod
%type <yaramod::TokenIt> string_id assign strings_value hex_integer hex_alt_left_bracket hex_alt_right_bracket hex_alt_operator hex_jump_left_bracket hex_jump_right_bracket left_bracket right_bracket integer_function integer_token
%type <yaramod::TokenIt> op_at op_in op_not op_and op_or op_lt op_gt op_le op_ge op_eq op_neq op_plus op_minus_unary op_minus_binary op_multiply op_divide op_modulo op_bw_xor op_bw_and op_bw_or op_bw_not op_shift_left op_shift_right op_contains op_matches left_bracket_range right_bracket_range double_dot
%type <yaramod::Rule> rule
%type <std::vector<yaramod::Meta>> metas metas_body
%type <std::shared_ptr<yaramod::Rule::StringsTrie>> strings strings_body
%type <std::shared_ptr<yaramod::String>> string
%type <std::pair<std::uint32_t, std::vector<TokenIt>>> string_mods
%type <yaramod::Literal> literal
%type <bool> boolean
%type <Expression::Ptr> condition expression primary_expression for_expression integer_set string_set range identifier
%type <std::vector<Expression::Ptr>> integer_enumeration string_enumeration arguments
%type <std::vector<TokenIt>> tags tag_list

%type <std::vector<std::shared_ptr<yaramod::HexStringUnit>>> hex_string hex_string_edge hex_string_body hex_byte
%type <std::shared_ptr<yaramod::HexStringUnit>> hex_or hex_jump
%type <std::vector<std::shared_ptr<yaramod::HexString>>> hex_or_body

%type <std::shared_ptr<yaramod::String>> regexp regexp_body
%type <std::shared_ptr<yaramod::RegexpUnit>> regexp_or regexp_repeat regexp_single
%type <std::vector<std::shared_ptr<yaramod::RegexpUnit>>> regexp_concat
%type <bool> regexp_greedy

%start rules

%left OR
%left AND
%left BITWISE_OR
%left BITWISE_XOR
%left BITWISE_AND
%left EQ NEQ
%left LT LE GT GE
%left SHIFT_LEFT SHIFT_RIGHT
%left PLUS MINUS
%left MULTIPLY DIVIDE MODULO
%right NOT BITWISE_NOT UNARY_MINUS

/**
 * Expect one shift/reduce conflict. This conflict happens most probably because of these rules
 *
 * expression -> ( expression )
 * expression -> primary_expression
 * primary_expression -> ( primary_expression )
 *
 * When bison parser sees ')', it can't decide whether to shift it
 * and continue with rule primary_expression -> ( primary_expression ),
 * or to reduce primary_expression to expression and then shift ')'.
 * In the end, it produces the same result both ways.
 */
%expect 131

%%

op_at : OP_AT { $$ = driver._tokenStream->emplace_back(OP_AT, "at"); }
op_in : OP_IN { $$ = driver._tokenStream->emplace_back(OP_IN, "in"); }
op_not : NOT { $$ = driver._tokenStream->emplace_back(NOT, "not"); }
op_and : AND { $$ = driver._tokenStream->emplace_back(AND, "and"); }
op_or : OR { $$ = driver._tokenStream->emplace_back(OR, "or"); }
op_lt : LT { $$ = driver._tokenStream->emplace_back(LT, "<"); }
op_gt : GT { $$ = driver._tokenStream->emplace_back(GT, ">"); }
op_le : LE { $$ = driver._tokenStream->emplace_back(LE, "<="); }
op_ge : GE { $$ = driver._tokenStream->emplace_back(GE, ">="); }
op_eq : EQ { $$ = driver._tokenStream->emplace_back(EQ, "=="); }
op_neq : NEQ { $$ = driver._tokenStream->emplace_back(NEQ, "!="); }
op_contains : CONTAINS { $$ = driver._tokenStream->emplace_back(CONTAINS, "contains"); }
op_matches : MATCHES { $$ = driver._tokenStream->emplace_back(MATCHES, "matches"); }

op_plus : PLUS { $$ = driver._tokenStream->emplace_back(PLUS, "+"); }
op_minus_unary : MINUS { $$ = driver._tokenStream->emplace_back(UNARY_MINUS, "-"); }
op_minus_binary : MINUS { $$ = driver._tokenStream->emplace_back(MINUS, "-"); }
op_multiply : MULTIPLY { $$ = driver._tokenStream->emplace_back(MULTIPLY, "*"); }
op_divide : DIVIDE { $$ = driver._tokenStream->emplace_back(DIVIDE, "\\"); }
op_modulo : MODULO { $$ = driver._tokenStream->emplace_back(MODULO, "%"); }
op_bw_xor : BITWISE_XOR { $$ = driver._tokenStream->emplace_back(BITWISE_XOR, "^"); }
op_bw_and : BITWISE_AND { $$ = driver._tokenStream->emplace_back(BITWISE_AND, "&"); }
op_bw_or : BITWISE_OR { $$ = driver._tokenStream->emplace_back(BITWISE_OR, "|"); }
op_bw_not : BITWISE_NOT { $$ = driver._tokenStream->emplace_back(BITWISE_NOT, "~"); }
op_shift_left : SHIFT_LEFT { $$ = driver._tokenStream->emplace_back(SHIFT_LEFT, "<<"); }
op_shift_right : SHIFT_RIGHT { $$ = driver._tokenStream->emplace_back(SHIFT_RIGHT, ">>"); }

rules
	: rules rule
	| rules import
	| rules END { YYACCEPT; }
	| %empty
	;

import
	: IMPORT_KEYWORD
		{
			driver._tokenStream->emplace_back(TokenType::IMPORT_KEYWORD, "import");
		}
		STRING_LITERAL[module]
		{
			TokenIt import = driver._tokenStream->emplace_back(TokenType::IMPORT_MODULE, $module);
			if (!driver._file.addImport(import))
			{
				error(driver.getLocation(), "Unrecognized module '" + $module + "' imported");
				YYABORT;
			}
		}
	;

rule
	: rule_mod RULE
		{
			driver.markStartOfRule();
		}
		ID[id]
		{
			if (driver.ruleExists($id))
			{
				error(driver.getLocation(), "Redefinition of rule '" + $id + "'");
				YYABORT;
			}
			driver.tmp_token = driver._tokenStream->emplace_back(TokenType::RULE_NAME, $id);
		}
		tags rule_begin
		metas strings condition rule_end
		{
			driver.addRule(Rule(driver._tokenStream, driver.tmp_token.value(), $rule_mod, std::move($metas), std::move($strings), std::move($condition), std::move($tags)));
			driver.tmp_token.reset();
		}
	;

rule_mod
	: GLOBAL { $$ = driver._tokenStream->emplace_back(TokenType::GLOBAL, "global"); }
	| PRIVATE { $$ = driver._tokenStream->emplace_back(TokenType::PRIVATE, "private"); }
	| %empty { $$ = std::nullopt; }
	;

tags
	: COLON tag_list { $$ = std::move($tag_list); }
	| %empty { $$.clear(); }
	;

rule_begin
	: LCB {driver._tokenStream->emplace_back(TokenType::RULE_BEGIN, "{");}
	;

rule_end
	: RCB {driver._tokenStream->emplace_back(TokenType::RULE_END, "}");}
	;

tag_list
	: tag_list ID
		{
			$$ = std::move($1);
			$$.push_back(driver._tokenStream->emplace_back(TokenType::TAG, std::move($2)));
		}
	| ID
	{
		$$.push_back(driver._tokenStream->emplace_back(TokenType::TAG, std::move($1)));
	}
	;

metas
	: metas_header metas_body
	{
		$$ = std::move($metas_body);
	}
	| %empty { $$.clear(); }
	;

metas_header
	: META COLON

metas_body
	: metas_body[body] ID ASSIGN literal
		{
			$$ = std::move($body);
			TokenIt key = driver._tokenStream->emplace_back(TokenType::META_KEY, std::move($2));
			driver._tokenStream->emplace_back(TokenType::EQ, "=");
			TokenIt val = driver._tokenStream->emplace_back(TokenType::META_VALUE, std::move($4));
			$$.emplace_back(key, val);
		}
	| %empty { $$.clear(); }
	;

strings
	: STRINGS COLON strings_body { $$ = std::move($strings_body); }
	| %empty
		{
			$$ = std::make_shared<Rule::StringsTrie>();
			driver.setCurrentStrings($$);
		}
	;

strings_body
	: strings_body[body] string_id[id] assign[assign_symbol]	string
		{
			$$ = std::move($body);

			auto trieId = driver.isAnonymousStringId($id->getPureText()) ? driver.generateAnonymousStringPseudoId() : $id->getPureText();
			$string->setIdentifier($id, $assign_symbol);

			if (!$$->insert(trieId, std::move($string)))
			{
				error(driver.getLocation(), "Redefinition of string '" + trieId + "'");
				YYABORT;
			}
		}
	| %empty
		{
			$$ = std::make_shared<Rule::StringsTrie>();
			driver.setCurrentStrings($$);
		}
	;

string_id
	: STRING_ID
	{
		$$ = driver._tokenStream->emplace_back(TokenType::STRING_ID, $1);
		// $$ = driver._tokenStream->emplace(--driver._tokenStream->end(), STRING_ID, $1);
	}

assign
	: ASSIGN
	{
		$$ = driver._tokenStream->emplace_back(TokenType::ASSIGN, "=");
	}

string
	: strings_value[value] string_mods
		{
			$$ = std::make_shared<PlainString>(driver._tokenStream, std::move($value));
			$$->setModifiers($string_mods.first, std::move($string_mods.second));
		}
	| LCB
		{
			driver._tokenStream->emplace_back(TokenType::HEX_START_BRACKET, "{ ");
			driver.getLexer().switchToHexLexer();
		}
		hex_string RCB
		{
			$$ = std::make_shared<HexString>(driver._tokenStream, std::move($hex_string));
			driver.getLexer().switchToYaraLexer();
			driver._tokenStream->emplace_back(TokenType::HEX_END_BRACKET, "}");
		}
	| regexp string_mods
		{
			$$ = std::move($regexp);
			$$->setModifiers($string_mods.first, std::move($string_mods.second));
		}
	;

strings_value
	: STRING_LITERAL
		{
			$$ = driver._tokenStream->emplace_back(TokenType::STRING_LITERAL, $1);
		}
	;

condition
	: CONDITION COLON expression { $$ = std::move($expression); }
	;

expression
	: boolean
		{
			if($1)
				$$ = std::make_shared<BoolLiteralExpression>(driver._tokenStream->emplace_back(BOOL_TRUE, $1));
			else
				$$ = std::make_shared<BoolLiteralExpression>(driver._tokenStream->emplace_back(BOOL_FALSE, $1));
			$$->setType(Expression::Type::Bool);
		}
	| string_id
		{
			if (!driver.stringExists($1->getString()))
			{
				error(driver.getLocation(), "Reference to undefined string '" + $1->getString() + "'");
				YYABORT;
			}
			$$ = std::make_shared<StringExpression>($1);
			$$->setType(Expression::Type::Bool);
		}
	| string_id op_at primary_expression
		{
			if (!driver.stringExists($1->getString()))
			{
				error(driver.getLocation(), "Reference to undefined string '" + $1->getString() + "'");
				YYABORT;
			}

			if (!$primary_expression->isInt())
			{
				error(driver.getLocation(), "operator 'at' expects integer on the right-hand side of the expression");
				YYABORT;
			}

			$$ = std::make_shared<StringAtExpression>($1, $2, std::move($primary_expression));
			$$->setType(Expression::Type::Bool);
		}
	| string_id op_in range
		{
			if (!driver.stringExists($1->getString()))
			{
				error(driver.getLocation(), "Reference to undefined string '" + $1->getString() + "'");
				YYABORT;
			}

			$$ = std::make_shared<StringInRangeExpression>($1, $2, std::move($range));
			$$->setType(Expression::Type::Bool);
		}
	| FOR for_expression ID[id]
		{
			auto symbol = std::make_shared<ValueSymbol>($id, Expression::Type::Int);
			driver._tokenStream->emplace_back(TokenType::FOR, symbol.get());
			if (!driver.addLocalSymbol(symbol))
			{
				error(driver.getLocation(), "Redefinition of identifier '" + $id + "'");
				YYABORT;
			}
		}
		OP_IN integer_set COLON LP expression[expr] RP
		{
			/* Delete $id before we move it to ForIntExpression */
			driver.removeLocalSymbol($id);
			$$ = std::make_shared<ForIntExpression>(std::move($for_expression), std::move($id), std::move($integer_set), std::move($expr));
			$$->setType(Expression::Type::Bool);
		}
	| FOR for_expression OF string_set
		{
			if (driver.isInStringLoop())
			{
				error(driver.getLocation(), "Nesting of for-loop over strings is not allowed");
				YYABORT;
			}

			driver.stringLoopEnter();
		}
		COLON LP expression[expr] RP
		{
			$$ = std::make_shared<ForStringExpression>(std::move($for_expression), std::move($string_set), std::move($expr));
			$$->setType(Expression::Type::Bool);

			driver.stringLoopLeave();
		}
	| for_expression OF string_set
		{
			$$ = std::make_shared<OfExpression>(std::move($for_expression), std::move($string_set));
			$$->setType(Expression::Type::Bool);
		}
	| op_not expression[expr]
		{
			$$ = std::make_shared<NotExpression>($1, std::move($expr));
			$$->setType(Expression::Type::Bool);
		}
	| expression[left] op_and expression[right]
		{
			$$ = std::make_shared<AndExpression>(std::move($left), std::move($right));
			$$->setType(Expression::Type::Bool);
		}
	| expression[left] op_or expression[right]
		{
			$$ = std::make_shared<OrExpression>(std::move($left), std::move($right));
			$$->setType(Expression::Type::Bool);
		}
	| primary_expression[left] op_lt primary_expression[right]
		{
			$$ = std::make_shared<LtExpression>(std::move($left), std::move($right));
			$$->setType(Expression::Type::Bool);
		}
	| primary_expression[left] op_gt primary_expression[right]
		{
			$$ = std::make_shared<GtExpression>(std::move($left), std::move($right));
			$$->setType(Expression::Type::Bool);
		}
	| primary_expression[left] op_le primary_expression[right]
		{
			$$ = std::make_shared<LeExpression>(std::move($left), std::move($right));
			$$->setType(Expression::Type::Bool);
		}
	| primary_expression[left] op_ge primary_expression[right]
		{
			$$ = std::make_shared<GeExpression>(std::move($left), std::move($right));
			$$->setType(Expression::Type::Bool);
		}
	| primary_expression[left] op_eq primary_expression[right]
		{
			$$ = std::make_shared<EqExpression>(std::move($left), std::move($right));
			$$->setType(Expression::Type::Bool);
		}
	| primary_expression[left] op_neq primary_expression[right]
		{
			$$ = std::make_shared<NeqExpression>(std::move($left), std::move($right));
			$$->setType(Expression::Type::Bool);
		}
	| primary_expression[left] op_contains primary_expression[right]
		{
			if (!$left->isString())
			{
				error(driver.getLocation(), "operator 'contains' expects string on the left-hand side of the expression");
				YYABORT;
			}

			if (!$right->isString())
			{
				error(driver.getLocation(), "operator 'contains' expects string on the right-hand side of the expression");
				YYABORT;
			}

			$$ = std::make_shared<ContainsExpression>(std::move($left), $2, std::move($right));
			$$->setType(Expression::Type::Bool);
		}
	| primary_expression[left] op_matches regexp[right]
		{
			if (!$left->isString())
			{
				error(driver.getLocation(), "operator 'matches' expects string on the left-hand side of the expression");
				YYABORT;
			}

			auto regexp = std::make_shared<RegexpExpression>(std::move($right));
			$$ = std::make_shared<MatchesExpression>(std::move($left), $2, std::move(regexp));
			$$->setType(Expression::Type::Bool);
		}
	| primary_expression
		{
			$$ = std::move($primary_expression);
		}
	| left_bracket expression[expr] right_bracket
		{
			auto type = $expr->getType();
			$$ = std::make_shared<ParenthesesExpression>($1, std::move($expr), $3);
			$$->setType(type);
		}
	;

left_bracket : LP { $$ = driver._tokenStream->emplace_back(LP, "("); }

right_bracket : RP { $$ = driver._tokenStream->emplace_back(RP, ")"); }

primary_expression // (primary_expression[expr]) | filesize | entrypoint |
	: left_bracket primary_expression[expr] right_bracket
		{
			auto type = $expr->getType();
			$$ = std::make_shared<ParenthesesExpression>($1, std::move($expr), $3);
			$$->setType(type);
		}
	| FILESIZE
		{
			TokenIt t = driver._tokenStream->emplace_back(FILESIZE, "filesize");
			$$ = std::make_shared<FilesizeExpression>(t);
			$$->setType(Expression::Type::Int);
		}
	| ENTRYPOINT
		{
			TokenIt t = driver._tokenStream->emplace_back(ENTRYPOINT, "entrypoint");
			$$ = std::make_shared<EntrypointExpression>(t);
			$$->setType(Expression::Type::Int);
		}
	| integer_token
		{
			$$ = std::make_shared<IntLiteralExpression>($1);
			$$->setType(Expression::Type::Int);
		}
	| DOUBLE
		{
			TokenIt t = driver._tokenStream->emplace_back(TokenType::DOUBLE, std::stod(std::move($1)));
			$$ = std::make_shared<DoubleLiteralExpression>(t);
			$$->setType(Expression::Type::Float);
		}
	| STRING_LITERAL
		{
			TokenIt t = driver._tokenStream->emplace_back(TokenType::STRING_LITERAL, std::move($1));
			$$ = std::make_shared<StringLiteralExpression>(t);
			$$->setType(Expression::Type::String);
		}
	| STRING_COUNT
		{
			// Replace '#' for '$' to get string id
			auto stringId = $1->getString();
			stringId[0] = '$';

			if (!driver.stringExists(stringId))
			{
				error(driver.getLocation(), "Reference to undefined string '" + $1->getString() + "'");
				YYABORT;
			}

			$$ = std::make_shared<StringCountExpression>($1);
			$$->setType(Expression::Type::Int);
		}
	| STRING_OFFSET
		{
			// Replace '@' for '$' to get string id
			auto stringId = $1->getString();
			stringId[0] = '$';

			if (!driver.stringExists(stringId))
			{
				error(driver.getLocation(), "Reference to undefined string '" + $1->getString() + "'");
				YYABORT;
			}

			$$ = std::make_shared<StringOffsetExpression>($1);
			$$->setType(Expression::Type::Int);
		}
	| STRING_OFFSET LSQB primary_expression RSQB
		{
			// Replace '@' for '$' to get string id
			auto stringId = $1->getString();
			stringId[0] = '$';

			if (!driver.stringExists(stringId))
			{
				error(driver.getLocation(), "Reference to undefined string '" + $1->getString() + "'");
				YYABORT;
			}

			$$ = std::make_shared<StringOffsetExpression>($1, std::move($3));
			$$->setType(Expression::Type::Int);
		}
	| STRING_LENGTH
		{
			// Replace '!' for '$' to get string id
			auto stringId = $1->getString();
			stringId[0] = '$';

			if (!driver.stringExists(stringId))
			{
				error(driver.getLocation(), "Reference to undefined string '" + $1->getString() + "'");
				YYABORT;
			}

			$$ = std::make_shared<StringLengthExpression>($1);
			$$->setType(Expression::Type::Int);
		}
	| STRING_LENGTH LSQB primary_expression RSQB
		{
			// Replace '!' for '$' to get string id
			auto stringId = $1->getString();
			stringId[0] = '$';

			if (!driver.stringExists(stringId))
			{
				error(driver.getLocation(), "Reference to undefined string '" + $1->getString() + "'");
				YYABORT;
			}

			$$ = std::make_shared<StringLengthExpression>($1, std::move($3));
			$$->setType(Expression::Type::Int);
		}
	| op_minus_unary primary_expression %prec UNARY_MINUS
		{
			if (!$2->isInt() && !$2->isFloat())
			{
				error(driver.getLocation(), "unary minus expects integer or float type");
				YYABORT;
			}

			auto type = $2->getType();
			$$ = std::make_shared<UnaryMinusExpression>($1, std::move($2));
			$$->setType(type);
		}
	| primary_expression op_plus primary_expression
		{
			if (!$1->isInt() && !$1->isFloat())
			{
				error(driver.getLocation(), "operator '+' expects integer or float on the left-hand side");
				YYABORT;
			}

			if (!$3->isInt() && !$3->isFloat())
			{
				error(driver.getLocation(), "operator '+' expects integer or float on the right-hand side");
				YYABORT;
			}

			auto type = ($1->isInt() && $3->isInt()) ? Expression::Type::Int : Expression::Type::Float;
			$$ = std::make_shared<PlusExpression>(std::move($1), $2, std::move($3));
			$$->setType(type);
		}
	| primary_expression op_minus_binary primary_expression
		{
			if (!$1->isInt() && !$1->isFloat())
			{
				error(driver.getLocation(), "operator '-' expects integer or float on the left-hand side");
				YYABORT;
			}

			if (!$3->isInt() && !$3->isFloat())
			{
				error(driver.getLocation(), "operator '-' expects integer or float on the right-hand side");
				YYABORT;
			}

			auto type = ($1->isInt() && $3->isInt()) ? Expression::Type::Int : Expression::Type::Float;
			$$ = std::make_shared<MinusExpression>(std::move($1), $2, std::move($3));
			$$->setType(type);
		}
	| primary_expression op_multiply primary_expression
		{
			if (!$1->isInt() && !$1->isFloat())
			{
				error(driver.getLocation(), "operator '*' expects integer or float on the left-hand side");
				YYABORT;
			}

			if (!$3->isInt() && !$3->isFloat())
			{
				error(driver.getLocation(), "operator '*' expects integer or float on the right-hand side");
				YYABORT;
			}

			auto type = ($1->isInt() && $3->isInt()) ? Expression::Type::Int : Expression::Type::Float;
			$$ = std::make_shared<MultiplyExpression>(std::move($1), $2, std::move($3));
			$$->setType(type);
		}
	| primary_expression op_divide primary_expression
		{
			if (!$1->isInt() && !$1->isFloat())
			{
				error(driver.getLocation(), "operator '\\' expects integer or float on the left-hand side");
				YYABORT;
			}

			if (!$3->isInt() && !$3->isFloat())
			{
				error(driver.getLocation(), "operator '\\' expects integer or float on the right-hand side");
				YYABORT;
			}

			auto type = ($1->isInt() && $3->isInt()) ? Expression::Type::Int : Expression::Type::Float;
			$$ = std::make_shared<DivideExpression>(std::move($1), $2, std::move($3));
			$$->setType(type);
		}
	| primary_expression op_modulo primary_expression
		{
			if (!$1->isInt())
			{
				error(driver.getLocation(), "operator '%' expects integer on the left-hand side");
				YYABORT;
			}

			if (!$3->isInt())
			{
				error(driver.getLocation(), "operator '%' expects integer on the right-hand side");
				YYABORT;
			}

			$$ = std::make_shared<ModuloExpression>(std::move($1), $2, std::move($3));
			$$->setType(Expression::Type::Int);
		}
	| primary_expression op_bw_xor primary_expression
		{
			if (!$1->isInt())
			{
				error(driver.getLocation(), "operator '^' expects integer on the left-hand side");
				YYABORT;
			}

			if (!$3->isInt())
			{
				error(driver.getLocation(), "operator '^' expects integer on the right-hand side");
				YYABORT;
			}

			$$ = std::make_shared<BitwiseXorExpression>(std::move($1), $2, std::move($3));
			$$->setType(Expression::Type::Int);
		}
	| primary_expression op_bw_and primary_expression
		{
			if (!$1->isInt())
			{
				error(driver.getLocation(), "operator '&' expects integer on the left-hand side");
				YYABORT;
			}

			if (!$3->isInt())
			{
				error(driver.getLocation(), "operator '&' expects integer on the right-hand side");
				YYABORT;
			}

			$$ = std::make_shared<BitwiseAndExpression>(std::move($1), $2, std::move($3));
			$$->setType(Expression::Type::Int);
		}
	| primary_expression op_bw_or primary_expression
		{
			if (!$1->isInt())
			{
				error(driver.getLocation(), "operator '|' expects integer on the left-hand side");
				YYABORT;
			}

			if (!$3->isInt())
			{
				error(driver.getLocation(), "operator '|' expects integer on the right-hand side");
				YYABORT;
			}

			$$ = std::make_shared<BitwiseOrExpression>(std::move($1), $2, std::move($3));
			$$->setType(Expression::Type::Int);
		}
	| op_bw_not primary_expression
		{
			if (!$2->isInt())
			{
				error(driver.getLocation(), "bitwise not expects integer");
				YYABORT;
			}

			$$ = std::make_shared<BitwiseNotExpression>($1, std::move($2));
			$$->setType(Expression::Type::Int);
		}
	| primary_expression op_shift_left primary_expression
		{
			if (!$1->isInt())
			{
				error(driver.getLocation(), "operator '<<' expects integer on the left-hand side");
				YYABORT;
			}

			if (!$3->isInt())
			{
				error(driver.getLocation(), "operator '<<' expects integer on the right-hand side");
				YYABORT;
			}

			$$ = std::make_shared<ShiftLeftExpression>(std::move($1), $2, std::move($3));
			$$->setType(Expression::Type::Int);
		}
	| primary_expression op_shift_right primary_expression
		{
			if (!$1->isInt())
			{
				error(driver.getLocation(), "operator '>>' expects integer on the left-hand side");
				YYABORT;
			}

			if (!$3->isInt())
			{
				error(driver.getLocation(), "operator '>>' expects integer on the right-hand side");
				YYABORT;
			}

			$$ = std::make_shared<ShiftRightExpression>(std::move($1), $2, std::move($3));
			$$->setType(Expression::Type::Int);
		}
	| integer_function left_bracket primary_expression right_bracket
		{
			if (!$3->isInt())
			{
				error(driver.getLocation(), "operator '" + $1->getString() + "' expects integer");
				YYABORT;
			}

			$$ = std::make_shared<IntFunctionExpression>(std::move($1), $2, std::move($3), $4);
			$$->setType(Expression::Type::Int);
		}
	| identifier
		{
			$$ = std::move($identifier);
		}
	| regexp
		{
			$$ = std::make_shared<RegexpExpression>(std::move($regexp));
			$$->setType(Expression::Type::Regexp);
		}
	; // konec primary_expression

integer_function : INTEGER_FUNCTION { $$ = driver._tokenStream->emplace_back(INTEGER_FUNCTION, $1); }

integer_token
	: INTEGER
		{
			int multiplier = 1;
			if($1.size() >= 2)
		   {
		      if(std::toupper($1.back()) == 'B')
		      {
		         if(std::toupper(*($1.end()-2)) == 'K')
	   		      multiplier = 1000;
		         else if(std::toupper(*($1.end()-2)) == 'M')
	   		      multiplier = 1000000;
		      }
	      }
			if($1.substr(0,2) == "0x" || $1.substr(0,2) == "0X")
				$$ = driver._tokenStream->emplace_back(TokenType::INTEGER, std::stol($1.substr(2)) * multiplier, $1);
			else if(multiplier != 1)
				$$ = driver._tokenStream->emplace_back(TokenType::INTEGER, std::stol(std::move($1)) * multiplier, $1);
			else
				$$ = driver._tokenStream->emplace_back(TokenType::INTEGER, std::stol(std::move($1)));
		}


range
	: left_bracket_range primary_expression[low] double_dot primary_expression[high] right_bracket_range
		{
			if (!$low->isInt())
			{
				error(driver.getLocation(), "operator '..' expects integer as lower bound of the interval");
				YYABORT;
			}

			if (!$high->isInt())
			{
				error(driver.getLocation(), "operator '..' expects integer as higher bound of the interval");
				YYABORT;
			}
			//TokenIt lp = driver._tokenStream->findBackwards(LP, $3);
			$$ = std::make_shared<RangeExpression>($1, std::move($low), $3, std::move($high), $5);
		}
	;

double_dot : RANGE { $$ = driver._tokenStream->emplace_back(DOUBLE_DOT, ".."); }
left_bracket_range : LP { $$ = driver._tokenStream->emplace_back(LP, "("); }
right_bracket_range : RP { $$ = driver._tokenStream->emplace_back(RP, ")"); }

for_expression
	: primary_expression { $$ = std::move($primary_expression); }
	| ALL
		{
			TokenIt t = driver._tokenStream->emplace_back(ALL, "all");
			$$ = std::make_shared<AllExpression>(t);
		}
	| ANY
		{
			TokenIt t = driver._tokenStream->emplace_back(ANY, "any");
			$$ = std::make_shared<AnyExpression>();
		}
	;

integer_set
	: LP integer_enumeration RP { $$ = std::make_shared<SetExpression>(std::move($integer_enumeration)); }
	| range { $$ = std::move($range); }
	;

integer_enumeration
	: primary_expression[expr]
		{
			if (!$expr->isInt())
			{
				error(driver.getLocation(), "integer set expects integer type");
				YYABORT;
			}

			$$.push_back(std::move($expr));
		}
	| integer_enumeration[enum] COMMA primary_expression[expr]
		{
			if (!$expr->isInt())
			{
				error(driver.getLocation(), "integer set expects integer type");
				YYABORT;
			}

			$$ = std::move($enum);
			$$.push_back(std::move($expr));
		}
	;

string_set
	: LP string_enumeration RP { $$ = std::make_shared<SetExpression>(std::move($string_enumeration)); }
	| THEM
		{
			TokenIt t = driver._tokenStream->emplace_back(THEM, "them");
			$$ = std::make_shared<ThemExpression>();
		}
	;

string_enumeration
	: STRING_ID[id]
		{
			if (!driver.stringExists($id))
			{
				error(driver.getLocation(), "Reference to undefined string '" + $id + "'");
				YYABORT;
			}

			$$.push_back(std::make_shared<StringExpression>(std::move($id)));
		}
	| STRING_ID_WILDCARD[id]
		{
			if (!driver.stringExists($id))
			{
				error(driver.getLocation(), "No string matched with wildcard '" + $id + "'");
				YYABORT;
			}

			$$.push_back(std::make_shared<StringWildcardExpression>(std::move($id)));
		}
	| string_enumeration[enum] COMMA STRING_ID[id]
		{
			if (!driver.stringExists($id))
			{
				error(driver.getLocation(), "Reference to undefined string '" + $id + "'");
				YYABORT;
			}

			$$ = std::move($enum);
			$$.push_back(std::make_shared<StringExpression>(std::move($id)));
		}
	| string_enumeration[enum] COMMA STRING_ID_WILDCARD[id]
		{
			if (!driver.stringExists($id))
			{
				error(driver.getLocation(), "No string matched with wildcard '" + $id + "'");
				YYABORT;
			}

			$$ = std::move($enum);
			$$.push_back(std::make_shared<StringWildcardExpression>(std::move($id)));
		}
	;

identifier
	: ID
		{
			auto symbol = driver.findSymbol($1);
			if (!symbol)
			{
				error(driver.getLocation(), "Unrecognized identifier '" + $1 + "' referenced");
				YYABORT;
			}

			$$ = std::make_shared<IdExpression>(symbol);
			$$->setType(symbol->getDataType());
		}
	| identifier DOT ID
		{
			if (!$1->isObject())
			{
				error(driver.getLocation(), "Identifier '" + $1->getText() + "' is not an object");
				YYABORT;
			}

			auto parentSymbol = std::static_pointer_cast<const IdExpression>($1)->getSymbol();
			if (!parentSymbol->isStructure())
			{
				error(driver.getLocation(), "Identifier '" + parentSymbol->getName() + "' is not a structure");
				YYABORT;
			}

			auto structParentSymbol = std::static_pointer_cast<const StructureSymbol>(parentSymbol);
			auto attr = structParentSymbol->getAttribute($3);
			if (!attr)
			{
				error(driver.getLocation(), "Unrecognized identifier '" + $3 + "' referenced");
				YYABORT;
			}

			auto symbol = attr.value();
			$$ = std::make_shared<StructAccessExpression>(symbol, std::move($1));
			$$->setType(symbol->getDataType());
		}
	| identifier LSQB primary_expression RSQB
		{
			if (!$1->isObject())
			{
				error(driver.getLocation(), "Identifier '" + $1->getText() + "' is not an object");
				YYABORT;
			}

			auto parentSymbol = std::static_pointer_cast<const IdExpression>($1)->getSymbol();
			if (!parentSymbol->isArray() && !parentSymbol->isDictionary())
			{
				error(driver.getLocation(), "Identifier '" + parentSymbol->getName() + "' is not an array nor dictionary");
				YYABORT;
			}

			auto iterParentSymbol = std::static_pointer_cast<const IterableSymbol>(parentSymbol);
			$$ = std::make_shared<ArrayAccessExpression>(iterParentSymbol->getStructuredElementType(), std::move($1), std::move($primary_expression));
			$$->setType(iterParentSymbol->getElementType());
		}
	| identifier LP arguments RP
		{
			if (!$1->isObject())
			{
				error(driver.getLocation(), "Identifier '" + $1->getText() + "' is not an object");
				YYABORT;
			}

			auto parentSymbol = std::static_pointer_cast<const IdExpression>($1)->getSymbol();
			if (!parentSymbol->isFunction())
			{
				error(driver.getLocation(), "Identifier '" + parentSymbol->getName() + "' is not a function");
				YYABORT;
			}

			auto funcParentSymbol = std::static_pointer_cast<const FunctionSymbol>(parentSymbol);

			// Make copy of just argument types because symbols are not aware of expressions
			std::vector<Expression::Type> argTypes;
			std::for_each($arguments.begin(), $arguments.end(),
				[&argTypes](const Expression::Ptr& expr)
				{
					argTypes.push_back(expr->getType());
				});

			if (!funcParentSymbol->overloadExists(argTypes))
			{
				std::cerr << "Unexpected argument types for function " << funcParentSymbol->getName() << " ( ";
				std::for_each($arguments.begin(), $arguments.end(),
					[](const Expression::Ptr& expr)
					{
						std::cerr << expr->getTypeString() << " ";
					});
				std::cerr << ")" << std::endl;
				error(driver.getLocation(), "No matching overload of function '" + funcParentSymbol->getName() + "' for these types of parameters");
				YYABORT;
			}

			$$ = std::make_shared<FunctionCallExpression>(std::move($1), std::move($arguments));
			$$->setType(funcParentSymbol->getReturnType());
		}
	;

arguments
	: arguments COMMA expression
		{
			$$ = std::move($1);
			$$.push_back(std::move($expression));
		}
	| expression { $$.push_back(std::move($expression)); }
	| %empty { $$.clear(); }
	;

string_mods
	: string_mods ASCII
		{
			uint32_t m1 = $1.first | String::Modifiers::Ascii;
			TokenIt t = driver._tokenStream->emplace_back(TokenType::ASCII, "ascii");
			$1.second.push_back(t);
			$$ = std::make_pair(m1, std::move($1.second));
		}
	| string_mods WIDE
		{
			uint32_t m1 = $1.first | String::Modifiers::Wide;
			TokenIt t = driver._tokenStream->emplace_back(TokenType::WIDE, "wide");
			$1.second.push_back(t);
			$$ = std::make_pair(m1, std::move($1.second));
		}
	| string_mods NOCASE
		{
			uint32_t m1 = $1.first | String::Modifiers::Nocase;
			TokenIt t = driver._tokenStream->emplace_back(TokenType::NOCASE, "nocase");
			$1.second.push_back(t);
			$$ = std::make_pair(m1, std::move($1.second));
		}
	| string_mods FULLWORD
		{
			uint32_t m1 = $1.first | String::Modifiers::Fullword;
			TokenIt t = driver._tokenStream->emplace_back(TokenType::FULLWORD, "fullword");
			$1.second.push_back(t);
			$$ = std::make_pair(m1, std::move($1.second));
		}
	| string_mods XOR
		{
			uint32_t m1 = $1.first | String::Modifiers::Xor;
			TokenIt t = driver._tokenStream->emplace_back(TokenType::XOR, "xor");
			$1.second.push_back(t);
			$$ = std::make_pair(m1, std::move($1.second));
		}
	| %empty { $$ = std::make_pair(String::Modifiers::None, std::move(std::vector<TokenIt>())); }
	;

literal
	: STRING_LITERAL
	{
		$$ = Literal(std::move($1));
	}
	| INTEGER
	{
		int64_t value = std::stoll($1);
		$$ = Literal(value, std::move($1));
	}
	| boolean { $$ = Literal($1); }
	;

boolean
	: BOOL_TRUE { $$ = true; }
	| BOOL_FALSE { $$ = false; }
	;

hex_string
	: hex_string_edge { $$ = std::move($hex_string_edge); }
	| hex_string_edge hex_string_body hex_string_edge
		{
			$$ = std::move($1);
			$$.reserve($$.size() + $2.size() + $3.size());
			std::move($2.begin(), $2.end(), std::back_inserter($$));
			std::move($3.begin(), $3.end(), std::back_inserter($$));
		}

hex_string_edge
	: hex_byte { $$ = std::move($hex_byte); }
	| hex_or { $$.push_back(std::move($hex_or)); }
	;

hex_byte
	: HEX_NIBBLE HEX_NIBBLE
		{
			uint8_t u1 = ('A' <= std::toupper($1[0]) && std::toupper($1[0]) <= 'F') ? std::toupper($1[0]) - 'A' + 10 : $1[0] - '0';
			auto unit1 = driver._tokenStream->emplace_back(TokenType::HEX_NIBBLE, u1, $1);
			auto first = std::make_shared<HexStringNibble>(std::move(unit1));
			uint8_t u2 = ('A' <= std::toupper($2[0]) && std::toupper($2[0]) <= 'F') ? std::toupper($2[0]) - 'A' + 10 : $2[0] - '0';
			auto unit2 = driver._tokenStream->emplace_back(TokenType::HEX_NIBBLE, u2, $2 + " ");
			auto second = std::make_shared<HexStringNibble>(std::move(unit2));
			$$.reserve(2);
			$$.push_back(std::move(first));
			$$.push_back(std::move(second));
		}
	| HEX_NIBBLE HEX_WILDCARD
		{
			uint8_t u1 = ('A' <= std::toupper($1[0]) && std::toupper($1[0]) <= 'F') ? std::toupper($1[0]) - 'A' + 10 : $1[0] - '0';
			TokenIt unit1 = driver._tokenStream->emplace_back(TokenType::HEX_NIBBLE, u1, $1);
			auto first = std::make_shared<HexStringNibble>(std::move(unit1));
			TokenIt unit2 = driver._tokenStream->emplace_back(TokenType::HEX_WILDCARD_HIGH, "? ");
			auto second = std::make_shared<HexStringWildcard>(std::move(unit2));
			$$.reserve(2);
			$$.push_back(std::move(first));
			$$.push_back(std::move(second));
		}
	| HEX_WILDCARD HEX_NIBBLE
		{
			TokenIt unit1 = driver._tokenStream->emplace_back(TokenType::HEX_WILDCARD_LOW, "?");
			auto first = std::make_shared<HexStringWildcard>(std::move(unit1));
			uint8_t u2 = ('A' <= std::toupper($2[0]) && std::toupper($2[0]) <= 'F') ? std::toupper($2[0]) - 'A' + 10 : $2[0] - '0';
			TokenIt unit2 = driver._tokenStream->emplace_back(TokenType::HEX_NIBBLE, u2, $2 + " ");
			auto second = std::make_shared<HexStringNibble>(std::move(unit2));
			$$.reserve(2);
			$$.push_back(std::move(first));
			$$.push_back(std::move(second));
		}
	| HEX_WILDCARD HEX_WILDCARD
		{
			TokenIt unit1 = driver._tokenStream->emplace_back(TokenType::HEX_WILDCARD_LOW, "?");
			auto first = std::make_shared<HexStringWildcard>(std::move(unit1));
			TokenIt unit2 = driver._tokenStream->emplace_back(TokenType::HEX_WILDCARD_HIGH, "? ");
			auto second = std::make_shared<HexStringWildcard>(std::move(unit2));
			$$.reserve(2);
			$$.push_back(std::move(first));
			$$.push_back(std::move(second));

			// TokenIt unit1 = driver._tokenStream->emplace_back(TokenType::HEX_WILDCARD_FULL, "?? ");
			// auto first = std::make_shared<HexStringWildcard>(std::move(unit1));
			// $$.reserve(1);
			// $$.push_back(std::move(first));
		}
	;

hex_string_body
	: hex_string_body[body] hex_byte
		{
			$$ = std::move($body);
			std::move($hex_byte.begin(), $hex_byte.end(), std::back_inserter($$));
		}
	| hex_string_body[body] hex_or
		{
			$$ = std::move($body);
			$$.push_back(std::move($hex_or));
		}
	| hex_string_body[body] hex_jump
		{
			$$ = std::move($body);
			$$.push_back(std::move($hex_jump));
		}
	| %empty { $$.clear(); }
	;

hex_or
	: hex_alt_left_bracket hex_or_body hex_alt_right_bracket { $$ = std::make_shared<HexStringOr>(std::move($hex_or_body)); }

hex_or_body //vektor<shared_ptr<HexString>>
	: hex_string_body
		{
			auto hexStr = std::make_shared<HexString>(driver._tokenStream, std::move($hex_string_body));
			$$.push_back(std::move(hexStr));
		}
	| hex_or_body[body] hex_alt_operator hex_string_body
		{
			$$ = std::move($body);
			auto hexStr = std::make_shared<HexString>(driver._tokenStream, std::move($hex_string_body)); //vektor<shared_ptr<HexStringUnit>>
			$$.push_back(std::move(hexStr));
		}
	;

hex_alt_operator
	: HEX_OR { $$ = driver._tokenStream->emplace_back(TokenType::HEX_ALT, "| "); }

hex_alt_left_bracket
	: LP { $$ = driver._tokenStream->emplace_back(TokenType::HEX_ALT_LEFT_BRACKET, "( "); }

hex_alt_right_bracket
	: RP { $$ = driver._tokenStream->emplace_back(TokenType::HEX_ALT_RIGHT_BRACKET, ") "); }

hex_jump
	: hex_jump_left_bracket hex_integer[value] hex_jump_right_bracket
		{
			$$ = std::make_shared<HexStringJump>($value, $value);
		}
	| hex_jump_left_bracket hex_integer[low] DASH hex_integer[high] hex_jump_right_bracket
		{
			// driver._tokenStream->emplace_back(TokenType::DASH, "-");
			$$ = std::make_shared<HexStringJump>($low, $high);
		}
	| hex_jump_left_bracket hex_integer[low] DASH hex_jump_right_bracket
		{
			$$ = std::make_shared<HexStringJump>($low);
		}
	| hex_jump_left_bracket DASH hex_jump_right_bracket
		{
			// driver._tokenStream->emplace_back(TokenType::DASH, "-");
			$$ = std::make_shared<HexStringJump>();
		}
	;
hex_integer
	: HEX_INTEGER {$$ = driver._tokenStream->emplace_back(TokenType::INTEGER, $1);}

hex_jump_left_bracket
	: LSQB { $$ = driver._tokenStream->emplace_back(TokenType::HEX_JUMP_LEFT_BRACKET, "["); }

hex_jump_right_bracket
	: RSQB { $$ = driver._tokenStream->emplace_back(TokenType::HEX_JUMP_RIGHT_BRACKET, "] "); }

regexp
	: SLASH
		{
			driver.getLexer().switchToRegexpLexer();
		}
		regexp_body SLASH[suffix_mods]
		{
			$$ = std::move($regexp_body);
			std::static_pointer_cast<Regexp>($$)->setSuffixModifiers($suffix_mods);
			driver.getLexer().switchToYaraLexer();
		}

regexp_body
	: regexp_or { $$ = std::make_shared<Regexp>(driver._tokenStream, std::move($regexp_or)); }
	;

regexp_or
	: regexp_concat { $$ = std::make_shared<RegexpConcat>(std::move($regexp_concat)); }
	| regexp_or REGEXP_OR regexp_concat
		{
			auto concat = std::make_shared<RegexpConcat>(std::move($regexp_concat));
			$$ = std::make_shared<RegexpOr>(std::move($1), std::move(concat));
		}
	;

regexp_concat
	: regexp_repeat { $$.push_back(std::move($1)); }
	| regexp_concat regexp_repeat
		{
			$$ = std::move($1);
			$$.push_back(std::move($2));
		}
	;

regexp_repeat
	: regexp_single REGEXP_ITER regexp_greedy { $$ = std::make_shared<RegexpIteration>(std::move($regexp_single), $regexp_greedy); }
	| regexp_single REGEXP_PITER regexp_greedy { $$ = std::make_shared<RegexpPositiveIteration>(std::move($regexp_single), $regexp_greedy); }
	| regexp_single REGEXP_OPTIONAL regexp_greedy { $$ = std::make_shared<RegexpOptional>(std::move($regexp_single), $regexp_greedy); }
	| regexp_single REGEXP_RANGE regexp_greedy
		{
			if (!$2.first && !$2.second)
			{
				error(driver.getLocation(), "Range in regular expression does not have defined lower bound nor higher bound");
				YYABORT;
			}

			if ($2.first && $2.second && $2.first.value() > $2.second.value())
			{
				error(driver.getLocation(), "Range in regular expression has greater lower bound than higher bound");
				YYABORT;
			}

			$$ = std::make_shared<RegexpRange>(std::move($regexp_single), std::move($2), $regexp_greedy);
		}
	| regexp_single { $$ = std::move($regexp_single); }
	| REGEXP_WORD_BOUNDARY { $$ = std::make_shared<RegexpWordBoundary>(); }
	| REGEXP_NON_WORD_BOUNDARY { $$ = std::make_shared<RegexpNonWordBoundary>(); }
	| REGEXP_START_OF_LINE { $$ = std::make_shared<RegexpStartOfLine>(); }
	| REGEXP_END_OF_LINE { $$ = std::make_shared<RegexpEndOfLine>(); }
	;

regexp_greedy
	: %empty { $$ = true; }
	| REGEXP_OPTIONAL { $$ = false; }
	;

regexp_single
	: LP regexp_or RP { $$ = std::make_shared<RegexpGroup>(std::move($2)); }
	| REGEXP_ANY_CHAR { $$ = std::make_shared<RegexpAnyChar>(); }
	| REGEXP_CHAR { $$ = std::make_shared<RegexpText>(std::move($1)); }
	| REGEXP_WORD_CHAR { $$ = std::make_shared<RegexpWordChar>(); }
	| REGEXP_NON_WORD_CHAR { $$ = std::make_shared<RegexpNonWordChar>(); }
	| REGEXP_SPACE { $$ = std::make_shared<RegexpSpace>(); }
	| REGEXP_NON_SPACE { $$ = std::make_shared<RegexpNonSpace>(); }
	| REGEXP_DIGIT { $$ = std::make_shared<RegexpDigit>(); }
	| REGEXP_NON_DIGIT { $$ = std::make_shared<RegexpNonDigit>(); }
	| REGEXP_CLASS[c]
		{
			// It is negative class
			if ($c[0] == '^')
				$$ = std::make_shared<RegexpClass>($c.substr(1, $c.length() - 1), true);
			else
				$$ = std::make_shared<RegexpClass>(std::move($c), false);
		}
	;

%%

// Bison expects implementation of error method by us
void yy::Parser::error(const yy::location& loc, const std::string& message)
{
	std::ostringstream os;
	os << "Error at " << loc << ": " << message;
	throw ParserError(os.str());
}
